package config

import (
	"ai-guardd/internal/types"
	"fmt"
	"os"
	"reflect"
	"strings"

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
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	expandEnvStrings(reflect.ValueOf(&cfg))
	validateConfig(&cfg)
	return &cfg, nil
}

func expandEnvStrings(value reflect.Value) {
	if !value.IsValid() {
		return
	}

	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			expandEnvStrings(value.Elem())
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			expandEnvStrings(value.Field(i))
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			expandEnvStrings(value.Index(i))
		}
	case reflect.String:
		if value.CanSet() {
			value.SetString(os.ExpandEnv(value.String()))
		}
	}
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
	if cfg.Output.AuditLogPath == "" {
		cfg.Output.AuditLogPath = "audit.log"
	}
	cfg.Dashboard.Port = normalizeDashboardPort(cfg.Dashboard.Port)
	if cfg.Dashboard.Port == "" {
		cfg.Dashboard.Port = ":8080"
	}
}

func normalizeDashboardPort(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return port
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return port
		}
	}
	return ":" + port
}
