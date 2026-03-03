package main

import (
	"context"
	"log"
	"log/slog"

	"github.com/pldespaigne/aa-cli/pkg/config"
	"github.com/pldespaigne/aa-cli/pkg/envio"
	"github.com/pldespaigne/aa-cli/pkg/util"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Config validation failed: %v", err)
	}

	client := envio.NewClient(cfg.EnvioApiToken,
		envio.WithRetryMaxTries(cfg.RetryMaxTries),
		envio.WithRetryInitialInterval(cfg.RetryInitialInterval),
		envio.WithRetryMaxInterval(cfg.RetryMaxInterval),
		envio.WithRetryMaxElapsedTime(cfg.RetryMaxElapsedTime),
	)

	query := envio.Query{
		FromBlock: 22_431_084,
		Logs:      []envio.LogSelection{},
		Transactions: []envio.TransactionSelection{
			{
				From:            []string{},
				To:              []string{},
				SigHash:         []string{},
				Status:          util.Ptr(uint(1)),
				Type:            []uint{4},
				ContractAddress: []string{},
			},
		},
		Traces: []envio.TraceSelection{},
		FieldSelection: envio.FieldSelection{
			Transaction: &[]string{"hash", "authorization_list"},
		},
		IncludeAllBlocks: false,
		JoinMode:         envio.JoinNothingMode,
	}

	type TxData struct {
		Hash              string `json:"hash"`
		AuthorizationList string `json:"authorization_list"`
	}

	type BlockData struct {
		Transactions []TxData `json:"transactions"`
	}

	logger := slog.Default()

	blocks, err := envio.ExecuteAll[BlockData](context.Background(), client, query, client.GetLogger())
	if err != nil {
		log.Fatalf("Failed to execute query: %v", err)
	}

	var txs []TxData
	for _, block := range blocks {
		txs = append(txs, block.Transactions...)
	}

	log.Printf("Total transactions: %d", len(txs))

	// Authority => []ContractAddress
	authorities := make(map[string]string)
	contracts := make(map[string]struct{})

	for _, tx := range txs {
		auths, err := envio.DecodeAuthorizationList(logger, tx.AuthorizationList)
		if err != nil {
			slog.Warn("failed to decode authorization list", "tx_hash", tx.Hash, "error", err)
			continue
		}
		for _, auth := range auths {
			_, exists := authorities[auth.Authority]
			if !exists {
				authorities[auth.Authority] = auth.ContractAddress
			} else if auth.ContractAddress == "0x0000000000000000000000000000000000000000" {
				delete(authorities, auth.Authority)
			} else {
				authorities[auth.Authority] = auth.ContractAddress
			}
			contracts[auth.ContractAddress] = struct{}{}
		}
	}

	slog.Info("analysis complete", "unique_authorities", len(authorities), "unique_contracts", len(contracts))
}
