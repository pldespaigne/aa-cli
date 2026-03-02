package main

import (
	"log"

	"github.com/pldespaigne/aa-cli/pkg/config"
	"github.com/pldespaigne/aa-cli/pkg/envio"
	"github.com/pldespaigne/aa-cli/pkg/util"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Config validation failed: %v", err)
	}

	client := envio.NewEnvioClient(uint64(1), cfg.EnvioApiToken)

	query := envio.EnvioQuery{
		FromBlock: 22_431_084,
		Logs:      []envio.EnvioLogSelection{},
		Transactions: []envio.EnvioTransactionSelection{
			{
				From:            []string{},
				To:              []string{},
				SigHash:         []string{},
				Status:          util.Ptr(uint(1)),
				Type:            []uint{4},
				ContractAddress: []string{},
			},
		},
		Traces: []envio.EnvioTraceSelection{},
		FieldSelection: envio.EnvioFieldSelection{
			Transaction: &[]string{"hash", "authorization_list"},
		},
		IncludeAllblocks: false,
		JoinMode:         envio.JoinNothingMode,
	}

	type TxData struct {
		Hash              string `json:"hash"`
		AuthorizationList string `json:"authorization_list"`
	}

	type BlockData struct {
		Transactions []TxData `json:"transactions"`
	}

	var txs []TxData
	i := 0
	for {
		if i > 10 {
			log.Printf("Reached maximum pagination limit, stopping")
			break
		}

		result, err := envio.Execute[BlockData](client, query)
		if err != nil {
			log.Fatalf("Failed to execute query: %v", err)
		}

		for _, block := range result.Data {
			txs = append(txs, block.Transactions...)
		}

		if result.ArchiveHeight == nil {
			log.Printf("Archive height not available, stopping pagination")
			break
		}

		log.Printf("Progress: block %d / %d", result.NextBlock, *result.ArchiveHeight)

		if result.NextBlock+10 >= *result.ArchiveHeight {
			break
		}

		query.FromBlock = result.NextBlock
		i++
	}

	log.Printf("Total transactions: %d", len(txs))

	// Authority => []ContractAddress
	authorities := make(map[string]string)
	contracts := make(map[string]struct{})

	for _, tx := range txs {
		auths, err := envio.DecodeAuthorizationList(tx.AuthorizationList)
		if err != nil {
			log.Printf("Failed to decode authorization list for transaction %s: %v", tx.Hash, err)
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

	log.Printf("Unique authorities: %d", len(authorities))
	log.Printf("Unique contracts: %d", len(contracts))
}
