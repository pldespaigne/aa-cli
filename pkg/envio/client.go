package envio

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type EnvioJoinMode string

const (
	DefaultMode     EnvioJoinMode = "Default"
	JoinAllMode     EnvioJoinMode = "JoinAll"
	JoinNothingMode EnvioJoinMode = "JoinNothing"
)

type EnvioLogSelection struct {
	Address []string   `json:"address"`
	Topics  [][]string `json:"topics"`
}

type EnvioTransactionSelection struct {
	From    []string `json:"from"`
	To      []string `json:"to"`
	SigHash []string `json:"sigHash"`

	Status *uint `json:"status,omitempty"`

	Type []uint `json:"type"`

	ContractAddress []string `json:"contract_address"`
}

type EnvioBlockSelection struct {
	Hash []string `json:"hash"`

	Miner []string `json:"miner"`
}

type EnvioTraceSelection struct {
	From    []string `json:"from"`
	To      []string `json:"to"`
	Address []string `json:"address"`

	CallType []string `json:"call_type"`

	RewardType []string `json:"reward_type"`

	Kind []string `json:"kind"`

	SigHash []string `json:"sighash"`
}

type EnvioFieldSelection struct {
	Block       *[]string `json:"block,omitempty"`
	Transaction *[]string `json:"transaction,omitempty"`
	Log         *[]string `json:"log,omitempty"`
	Trace       *[]string `json:"trace,omitempty"`
}

type EnvioQuery struct {
	FromBlock uint64  `json:"from_block"`
	ToBlock   *uint64 `json:"to_block,omitempty"`

	Logs         []EnvioLogSelection         `json:"logs"`
	Transactions []EnvioTransactionSelection `json:"transactions"`
	Traces       []EnvioTraceSelection       `json:"traces"`

	IncludeAllblocks bool                `json:"include_all_blocks"`
	FieldSelection   EnvioFieldSelection `json:"field_selection"`

	MaxNumBlocks       *uint `json:"max_num_blocks,omitempty"`
	MaxNumTransactions *uint `json:"max_num_transactions,omitempty"`
	MaxNumLogs         *uint `json:"max_num_logs,omitempty"`
	MaxNumTraces       *uint `json:"max_num_traces,omitempty"`

	JoinMode EnvioJoinMode `json:"join_mode"`
}

type EnvioRollbackGuard struct {
	BlockNumber      uint64 `json:"block_number"`
	Timestamp        uint64 `json:"timestamp"`
	Hash             string `json:"hash"`
	FirstBlockNumber uint64 `json:"first_block_number"`
	FirstParentHash  string `json:"first_parent_hash"`
}

type EnvioResponse[T any] struct {
	ArchiveHeight      *uint64             `json:"archive_height,omitempty"`
	NextBlock          uint64              `json:"next_block"`
	TotalExecutionTime uint64              `json:"total_execution_time"`
	Data               []T                 `json:"data"`
	RollbackGuard      *EnvioRollbackGuard `json:"rollback_guard,omitempty"`
}

type EnvioClient struct {
	ChainId  uint64
	ApiToken string
}

func NewEnvioClient(chainId uint64, apiToken string) *EnvioClient {
	return &EnvioClient{
		ChainId:  chainId,
		ApiToken: apiToken,
	}
}

func Execute[T any](c *EnvioClient, q EnvioQuery) (*EnvioResponse[T], error) {
	url := fmt.Sprintf("https://%d.hypersync.xyz/query", c.ChainId)

	jsonData, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiToken)

	httpClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var result EnvioResponse[T]
	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

type Authorization struct {
	ChainId         string
	ContractAddress string
	Nonce           string
	YParity         string
	R               string
	S               string
	Hash            string
	Authority       string
}

// Envio indexer has a bug in the way the store/formats the authorization list
func DecodeAuthorizationList(authList string) ([]Authorization, error) {
	// if the string starts with 0x, remove it
	authList = strings.TrimPrefix(authList, "0x")

	// verify that the string is a valid hex string
	decodedBytes, err := hex.DecodeString(authList)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %v", err)
	}
	if len(decodedBytes) < 8 {
		return nil, fmt.Errorf("invalid authorization list: expected at least 8 bytes, got %d", len(decodedBytes))
	}

	// the first 8 bytes represent the length of the list
	listLength := binary.LittleEndian.Uint64(decodedBytes[:8])

	result := make([]Authorization, 0, listLength)

	currentIndex := uint64(8)
	for range listLength {
		auth := Authorization{}

		chainIdLength := binary.LittleEndian.Uint64(decodedBytes[currentIndex : currentIndex+8])
		currentIndex += 8

		auth.ChainId = string(decodedBytes[currentIndex : currentIndex+chainIdLength])
		chainId, err := strconv.ParseUint(strings.TrimPrefix(auth.ChainId, "0x"), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chain ID: %v", err)
		}
		currentIndex += chainIdLength

		contractAddressLength := binary.LittleEndian.Uint64(decodedBytes[currentIndex : currentIndex+8])
		currentIndex += 8

		auth.ContractAddress = string(decodedBytes[currentIndex : currentIndex+contractAddressLength])
		bytesContractAddress, err := hex.DecodeString(strings.TrimPrefix(auth.ContractAddress, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid contract address: %v", err)
		}
		currentIndex += contractAddressLength

		nonceLength := binary.LittleEndian.Uint64(decodedBytes[currentIndex : currentIndex+8])
		currentIndex += 8

		auth.Nonce = string(decodedBytes[currentIndex : currentIndex+nonceLength])
		nonce, err := strconv.ParseUint(strings.TrimPrefix(auth.Nonce, "0x"), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid nonce: %v", err)
		}
		currentIndex += nonceLength

		yParityLength := binary.LittleEndian.Uint64(decodedBytes[currentIndex : currentIndex+8])
		currentIndex += 8

		auth.YParity = string(decodedBytes[currentIndex : currentIndex+yParityLength])
		vHex := strings.TrimPrefix(auth.YParity, "0x")
		if len(vHex)%2 != 0 {
			vHex = "0" + vHex
		}
		v, err := hex.DecodeString(vHex)
		if err != nil {
			return nil, fmt.Errorf("invalid yParity: %v", err)
		}
		currentIndex += yParityLength

		rLength := binary.LittleEndian.Uint64(decodedBytes[currentIndex : currentIndex+8])
		currentIndex += 8

		auth.R = string(decodedBytes[currentIndex : currentIndex+rLength])
		rHex := strings.TrimPrefix(auth.R, "0x")
		if len(rHex)%2 != 0 {
			rHex = "0" + rHex
		}
		r, err := hex.DecodeString(rHex)
		if err != nil {
			return nil, fmt.Errorf("invalid r: %v", err)
		}
		currentIndex += rLength

		sLength := binary.LittleEndian.Uint64(decodedBytes[currentIndex : currentIndex+8])
		currentIndex += 8

		auth.S = string(decodedBytes[currentIndex : currentIndex+sLength])
		sHex := strings.TrimPrefix(auth.S, "0x")
		if len(sHex)%2 != 0 {
			sHex = "0" + sHex
		}
		s, err := hex.DecodeString(sHex)
		if err != nil {
			return nil, fmt.Errorf("invalid s: %v", err)
		}
		currentIndex += sLength

		encoded, err := rlp.EncodeToBytes(struct {
			ChainId         uint64
			ContractAddress []byte
			Nonce           uint64
		}{
			ChainId:         chainId,
			ContractAddress: bytesContractAddress,
			Nonce:           nonce,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encode authorization: %v", err)
		}

		hash := crypto.Keccak256Hash(append([]byte{0x05}, encoded...))
		auth.Hash = hash.Hex()

		sig := make([]byte, 65)
		copy(sig[32-len(r):32], r)
		copy(sig[64-len(s):64], s)
		sig[64] = v[len(v)-1]
		recoveredPubKey, err := crypto.Ecrecover(hash.Bytes(), sig)
		if err != nil {
			log.Printf("Failed to recover public key for authorization")
			log.Printf("Hash: %s", auth.Hash)
			log.Printf("R: %s", auth.R)
			log.Printf("S: %s", auth.S)
			log.Printf("V: %s", auth.YParity)
			log.Printf("Signature: %s", hex.EncodeToString(sig))
			return nil, fmt.Errorf("failed to recover public key: %v", err)
		}

		// 4. Convert Public Key Bytes to Ethereum Address
		pubKey, err := crypto.UnmarshalPubkey(recoveredPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
		}
		auth.Authority = "0x" + hex.EncodeToString(crypto.PubkeyToAddress(*pubKey).Bytes())

		result = append(result, auth)
	}

	return result, nil
}
