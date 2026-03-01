package main

import (
	"fmt"
	"log"

	"github.com/pldespaigne/aa-cli/pkg/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Config validation failed: %v", err)
	}

	fmt.Printf("Loaded Config: %+v\n", cfg)
}
