package csbouncer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the common configuration for CrowdSec bouncers
type Config struct {
	APIKey                 string   `yaml:"api_key"`
	APIUrl                 string   `yaml:"api_url"`
	InsecureSkipVerify     *bool    `yaml:"insecure_skip_verify"`
	CertPath               string   `yaml:"cert_path"`
	KeyPath                string   `yaml:"key_path"`
	CAPath                 string   `yaml:"ca_cert_path"`
	RetryInitialConnect    bool     `yaml:"retry_initial_connect"`
	TickerInterval         string   `yaml:"update_frequency"`
	Scopes                 []string `yaml:"scopes"`
	ScenariosContaining    []string `yaml:"scenarios_containing"`
	ScenariosNotContaining []string `yaml:"scenarios_not_containing"`
	Origins                []string `yaml:"origins"`
	UserAgent              string   `yaml:"user_agent"`
}

// Validate validates the configuration and sets defaults
func (c *Config) Validate() error {
	if c.APIUrl == "" {
		return errors.New("config does not contain LAPI url")
	}

	if !strings.HasSuffix(c.APIUrl, "/") {
		c.APIUrl += "/"
	}

	if c.APIKey == "" && c.CertPath == "" && c.KeyPath == "" {
		return errors.New("config does not contain LAPI key or certificate")
	}

	if c.TickerInterval == "" {
		c.TickerInterval = "10s"
	}

	if c.UserAgent == "" {
		c.UserAgent = "go-cs-bouncer"
	}

	return nil
}

// GetTickerDuration parses and returns the ticker interval as a duration
func (c *Config) GetTickerDuration() (time.Duration, error) {
	duration, err := time.ParseDuration(c.TickerInterval)
	if err != nil {
		return 0, fmt.Errorf("unable to parse lapi update interval '%s': %w", c.TickerInterval, err)
	}

	if duration <= 0 {
		return 0, errors.New("lapi update interval must be positive")
	}

	return duration, nil
}

// LoadConfig loads configuration from a file path
func LoadConfig(configPath string) (*Config, error) {
	reader, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file '%s': %w", configPath, err)
	}
	defer reader.Close()

	return LoadConfigFromReader(reader)
}

// LoadConfigFromReader loads configuration from an io.Reader
func LoadConfigFromReader(configReader io.Reader) (*Config, error) {
	content, err := io.ReadAll(configReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read configuration: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}
