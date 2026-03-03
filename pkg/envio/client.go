package envio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"
)

type JoinMode string

const (
	DefaultMode     JoinMode = "Default"
	JoinAllMode     JoinMode = "JoinAll"
	JoinNothingMode JoinMode = "JoinNothing"
)

type LogSelection struct {
	Address []string   `json:"address"`
	Topics  [][]string `json:"topics"`
}

type TransactionSelection struct {
	From    []string `json:"from"`
	To      []string `json:"to"`
	SigHash []string `json:"sigHash"`

	Status *uint `json:"status,omitempty"`

	Type []uint `json:"type"`

	ContractAddress []string `json:"contract_address"`
}

type BlockSelection struct {
	Hash []string `json:"hash"`

	Miner []string `json:"miner"`
}

type TraceSelection struct {
	From    []string `json:"from"`
	To      []string `json:"to"`
	Address []string `json:"address"`

	CallType []string `json:"call_type"`

	RewardType []string `json:"reward_type"`

	Kind []string `json:"kind"`

	SigHash []string `json:"sighash"`
}

type FieldSelection struct {
	Block       *[]string `json:"block,omitempty"`
	Transaction *[]string `json:"transaction,omitempty"`
	Log         *[]string `json:"log,omitempty"`
	Trace       *[]string `json:"trace,omitempty"`
}

type Query struct {
	FromBlock uint64  `json:"from_block"`
	ToBlock   *uint64 `json:"to_block,omitempty"`

	Logs         []LogSelection         `json:"logs"`
	Transactions []TransactionSelection `json:"transactions"`
	Traces       []TraceSelection       `json:"traces"`

	IncludeAllBlocks bool           `json:"include_all_blocks"`
	FieldSelection   FieldSelection `json:"field_selection"`

	MaxNumBlocks       *uint `json:"max_num_blocks,omitempty"`
	MaxNumTransactions *uint `json:"max_num_transactions,omitempty"`
	MaxNumLogs         *uint `json:"max_num_logs,omitempty"`
	MaxNumTraces       *uint `json:"max_num_traces,omitempty"`

	JoinMode JoinMode `json:"join_mode"`
}

type RollbackGuard struct {
	BlockNumber      uint64 `json:"block_number"`
	Timestamp        uint64 `json:"timestamp"`
	Hash             string `json:"hash"`
	FirstBlockNumber uint64 `json:"first_block_number"`
	FirstParentHash  string `json:"first_parent_hash"`
}

type Response[T any] struct {
	ArchiveHeight      *uint64        `json:"archive_height,omitempty"`
	NextBlock          uint64         `json:"next_block"`
	TotalExecutionTime uint64         `json:"total_execution_time"`
	Data               []T            `json:"data"`
	RollbackGuard      *RollbackGuard `json:"rollback_guard,omitempty"`
}

type Querier interface {
	QueryRaw(ctx context.Context, q Query) ([]byte, error)
}

type Client struct {
	apiToken   string
	baseUrl    string
	httpClient *http.Client
	logger     *slog.Logger

	maxRetries           uint
	retryInitialInterval time.Duration
	retryMaxInterval     time.Duration
	retryMaxElapsedTime  time.Duration
}

type ClientOption func(*Client)

func WithBaseUrl(url string) ClientOption {
	return func(c *Client) {
		c.baseUrl = url
	}
}

func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

func WithLogger(l *slog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = l
	}
}

func WithRetryMaxTries(n uint) ClientOption {
	return func(c *Client) {
		c.maxRetries = n
	}
}

func WithRetryInitialInterval(d time.Duration) ClientOption {
	return func(c *Client) {
		c.retryInitialInterval = d
	}
}

func WithRetryMaxInterval(d time.Duration) ClientOption {
	return func(c *Client) {
		c.retryMaxInterval = d
	}
}

func WithRetryMaxElapsedTime(d time.Duration) ClientOption {
	return func(c *Client) {
		c.retryMaxElapsedTime = d
	}
}

func NewClient(apiToken string, opts ...ClientOption) *Client {
	c := &Client{
		apiToken:   apiToken,
		baseUrl:    "https://1.hypersync.xyz",
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     slog.Default(),

		maxRetries:           5,
		retryInitialInterval: 500 * time.Millisecond,
		retryMaxInterval:     30 * time.Second,
		retryMaxElapsedTime:  2 * time.Minute,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) GetLogger() *slog.Logger {
	return c.logger
}

func (c *Client) QueryRaw(ctx context.Context, q Query) ([]byte, error) {
	url := c.baseUrl + "/query"

	jsonData, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = c.retryInitialInterval
	bo.MaxInterval = c.retryMaxInterval

	operation := func() ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, backoff.Permanent(fmt.Errorf("failed to create request: %w", err))
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiToken)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Network errors are retryable
			return nil, fmt.Errorf("failed to execute request: %w", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			return bodyBytes, nil
		}

		apiErr := fmt.Errorf("hypersync API error: status %d, body: %s", resp.StatusCode, string(bodyBytes))

		// 429 Too Many Requests: honour Retry-After header if present
		if resp.StatusCode == http.StatusTooManyRequests {
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, err := strconv.Atoi(ra); err == nil {
					return nil, backoff.RetryAfter(seconds)
				}
			}
			return nil, apiErr // retryable with normal backoff
		}

		// 5xx Server errors: retryable
		if resp.StatusCode >= 500 {
			return nil, apiErr
		}

		// All other 4xx: not retryable
		return nil, backoff.Permanent(apiErr)
	}

	result, err := backoff.Retry(ctx, operation,
		backoff.WithBackOff(bo),
		backoff.WithMaxTries(c.maxRetries),
		backoff.WithMaxElapsedTime(c.retryMaxElapsedTime),
		backoff.WithNotify(func(err error, next time.Duration) {
			c.logger.Warn("retrying hypersync request", "error", err, "next_retry_in", next)
		}),
	)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func Execute[T any](ctx context.Context, q Querier, query Query) (*Response[T], error) {
	raw, err := q.QueryRaw(ctx, query)
	if err != nil {
		return nil, err
	}

	var result Response[T]
	err = json.Unmarshal(raw, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

func ExecuteAll[T any](ctx context.Context, q Querier, query Query, logger *slog.Logger) ([]T, error) {
	var all []T
	for {
		result, err := Execute[T](ctx, q, query)
		if err != nil {
			return nil, err
		}

		all = append(all, result.Data...)

		if result.ArchiveHeight == nil {
			logger.Warn("archive height not available, stopping pagination")
			break
		}

		logger.Info("pagination progress", "next_block", result.NextBlock, "archive_height", *result.ArchiveHeight)

		if result.NextBlock >= *result.ArchiveHeight {
			break
		}

		query.FromBlock = result.NextBlock
	}
	return all, nil
}
