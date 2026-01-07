package config

import (
	"ai-guardd/internal/types"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadConfig reads the configuration from the given path
func LoadConfig(path string) (*types.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer f.Close()

	var cfg types.Config
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	validateConfig(&cfg)
	return &cfg, nil
}

// validateConfig applies defaults and hard rules
func validateConfig(cfg *types.Config) {
	// Security: Force ExternalAI to false if not explicitly set (already default bool, but good to be explicit in logic if needed)
	if cfg.Input.AuthLogPath == "" {
		cfg.Input.AuthLogPath = "/var/log/auth.log"
	}
	// Detection defaults
	if cfg.Detection.LocalLLMUrl == "" {
		cfg.Detection.LocalLLMUrl = "http://localhost:11434/api/generate"
	}
	if cfg.Detection.LocalLLMModel == "" {
		cfg.Detection.LocalLLMModel = "tinyllama"
	}

	if cfg.Output.Format == "" {
		cfg.Output.Format = "json"
	}
}
