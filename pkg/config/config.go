package config

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	EnvioApiToken string `env:"ENVIO_API_TOKEN,required"`

	RetryMaxTries        uint          `env:"RETRY_MAX_TRIES"        envDefault:"5"`
	RetryInitialInterval time.Duration `env:"RETRY_INITIAL_INTERVAL" envDefault:"500ms"`
	RetryMaxInterval     time.Duration `env:"RETRY_MAX_INTERVAL"     envDefault:"30s"`
	RetryMaxElapsedTime  time.Duration `env:"RETRY_MAX_ELAPSED_TIME" envDefault:"2m"`
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		slog.Info("no .env file found, loading environment variables from the system")
	}

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse environment variables: %w", err)
	}

	return cfg, nil
}
