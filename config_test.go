package csbouncer

import (
	"strings"
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with API key",
			config: &Config{
				APIKey: "test-key",
				APIUrl: "http://localhost:8080",
			},
			wantErr: false,
		},
		{
			name: "valid config with certificates",
			config: &Config{
				CertPath: "/path/to/cert.pem",
				KeyPath:  "/path/to/key.pem",
				APIUrl:   "https://localhost:8081",
			},
			wantErr: false,
		},
		{
			name: "missing API URL",
			config: &Config{
				APIKey: "test-key",
			},
			wantErr: true,
			errMsg:  "config does not contain LAPI url",
		},
		{
			name: "missing authentication",
			config: &Config{
				APIUrl: "http://localhost:8080",
			},
			wantErr: true,
			errMsg:  "config does not contain LAPI key or certificate",
		},
		{
			name: "URL without trailing slash gets fixed",
			config: &Config{
				APIKey: "test-key",
				APIUrl: "http://localhost:8080",
			},
			wantErr: false,
		},
		{
			name: "sets default ticker interval",
			config: &Config{
				APIKey: "test-key",
				APIUrl: "http://localhost:8080/",
			},
			wantErr: false,
		},
		{
			name: "sets default user agent",
			config: &Config{
				APIKey: "test-key",
				APIUrl: "http://localhost:8080/",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Config.Validate() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Config.Validate() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("Config.Validate() error = %v, want no error", err)
				return
			}

			// Check that URL gets trailing slash
			if !strings.HasSuffix(tt.config.APIUrl, "/") {
				t.Errorf("Config.Validate() should add trailing slash to URL")
			}

			// Check default values are set
			if tt.config.TickerInterval == "" {
				t.Errorf("Config.Validate() should set default TickerInterval")
			}
			if tt.config.UserAgent == "" {
				t.Errorf("Config.Validate() should set default UserAgent")
			}
		})
	}
}

func TestConfig_GetTickerDuration(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		want     time.Duration
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid duration",
			interval: "30s",
			want:     30 * time.Second,
			wantErr:  false,
		},
		{
			name:     "valid duration with minutes",
			interval: "5m",
			want:     5 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "invalid duration format",
			interval: "invalid",
			wantErr:  true,
			errMsg:   "unable to parse lapi update interval",
		},
		{
			name:     "zero duration",
			interval: "0s",
			wantErr:  true,
			errMsg:   "lapi update interval must be positive",
		},
		{
			name:     "negative duration",
			interval: "-10s",
			wantErr:  true,
			errMsg:   "lapi update interval must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{TickerInterval: tt.interval}
			got, err := config.GetTickerDuration()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Config.GetTickerDuration() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Config.GetTickerDuration() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("Config.GetTickerDuration() error = %v, want no error", err)
				return
			}

			if got != tt.want {
				t.Errorf("Config.GetTickerDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Test file not found
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Errorf("LoadConfig() with nonexistent file should return error")
	}
	if !strings.Contains(err.Error(), "unable to read config file") {
		t.Errorf("LoadConfig() error should mention file reading issue")
	}
}

func TestLoadConfigFromReader(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid YAML",
			yaml: `
api_key: test-key
api_url: http://localhost:8080
update_frequency: 30s
`,
			wantErr: false,
		},
		{
			name: "invalid YAML",
			yaml: `
api_key: test-key
api_url: [invalid yaml structure
`,
			wantErr: true,
			errMsg:  "unable to unmarshal config file",
		},
		{
			name: "valid YAML but invalid config",
			yaml: `
# Missing required fields
update_frequency: 30s
`,
			wantErr: true,
			errMsg:  "config does not contain LAPI url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.yaml)
			config, err := LoadConfigFromReader(reader)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadConfigFromReader() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("LoadConfigFromReader() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("LoadConfigFromReader() error = %v, want no error", err)
				return
			}

			if config == nil {
				t.Errorf("LoadConfigFromReader() returned nil config")
			}
		})
	}
}
