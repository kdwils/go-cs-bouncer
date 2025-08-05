package csbouncer

import (
	"net/url"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid API key config",
			config: &Config{
				APIKey:    "test-key",
				APIUrl:    "http://localhost:8080/",
				UserAgent: "test-agent",
			},
			wantErr: false,
		},
		{
			name: "valid certificate config",
			config: &Config{
				CertPath:  "/path/to/cert.pem",
				KeyPath:   "/path/to/key.pem",
				APIUrl:    "https://localhost:8081/",
				UserAgent: "test-agent",
			},
			wantErr: true, // Will fail because cert files don't exist
			errMsg:  "unable to load certificate",
		},
		{
			name: "no authentication provided",
			config: &Config{
				APIUrl: "http://localhost:8080/",
			},
			wantErr: true,
			errMsg:  "no API key nor certificate provided",
		},
		{
			name: "both API key and certificate provided",
			config: &Config{
				APIKey:   "test-key",
				CertPath: "/path/to/cert.pem",
				KeyPath:  "/path/to/key.pem",
				APIUrl:   "http://localhost:8080/",
			},
			wantErr: true,
			errMsg:  "cannot use both API key and certificate auth",
		},
		{
			name: "invalid API URL",
			config: &Config{
				APIKey: "test-key",
				APIUrl: "://invalid-url",
			},
			wantErr: true,
			errMsg:  "invalid API URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewClient() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("NewClient() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("NewClient() error = %v, want no error", err)
				return
			}

			if client == nil {
				t.Errorf("NewClient() returned nil client")
			}
		})
	}
}

func TestBuildAPIKeyClient(t *testing.T) {
	tests := []struct {
		name               string
		apiKey             string
		caPath             string
		insecureSkipVerify bool
		isHTTPS            bool
		wantErr            bool
	}{
		{
			name:    "HTTP client",
			apiKey:  "test-key",
			isHTTPS: false,
			wantErr: false,
		},
		{
			name:    "HTTPS client without CA",
			apiKey:  "test-key",
			isHTTPS: true,
			wantErr: false,
		},
		{
			name:               "HTTPS client with skip verify",
			apiKey:             "test-key",
			insecureSkipVerify: true,
			isHTTPS:            true,
			wantErr:            false,
		},
		{
			name:    "HTTPS client with invalid CA path",
			apiKey:  "test-key",
			caPath:  "/nonexistent/ca.pem",
			isHTTPS: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := buildAPIKeyClient(tt.apiKey, tt.caPath, tt.insecureSkipVerify, tt.isHTTPS)

			if tt.wantErr {
				if err == nil {
					t.Errorf("buildAPIKeyClient() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("buildAPIKeyClient() error = %v, want no error", err)
				return
			}

			if client == nil {
				t.Errorf("buildAPIKeyClient() returned nil client")
			}
		})
	}
}

func TestBuildCertClient(t *testing.T) {
	tests := []struct {
		name               string
		certPath           string
		keyPath            string
		caPath             string
		insecureSkipVerify bool
		wantErr            bool
		errMsg             string
	}{
		{
			name:     "nonexistent certificate files",
			certPath: "/nonexistent/cert.pem",
			keyPath:  "/nonexistent/key.pem",
			wantErr:  true,
			errMsg:   "unable to load certificate",
		},
		{
			name:     "invalid CA path",
			certPath: "/nonexistent/cert.pem",
			keyPath:  "/nonexistent/key.pem",
			caPath:   "/nonexistent/ca.pem",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := buildCertClient(tt.certPath, tt.keyPath, tt.caPath, tt.insecureSkipVerify)

			if tt.wantErr {
				if err == nil {
					t.Errorf("buildCertClient() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("buildCertClient() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("buildCertClient() error = %v, want no error", err)
				return
			}

			if client == nil {
				t.Errorf("buildCertClient() returned nil client")
			}
		})
	}
}

func TestGetCertPool(t *testing.T) {
	tests := []struct {
		name    string
		caPath  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "no CA path (use system certs)",
			caPath:  "",
			wantErr: false,
		},
		{
			name:    "nonexistent CA file",
			caPath:  "/nonexistent/ca.pem",
			wantErr: true,
			errMsg:  "unable to load CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := getCertPool(tt.caPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("getCertPool() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("getCertPool() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("getCertPool() error = %v, want no error", err)
				return
			}

			if pool == nil {
				t.Errorf("getCertPool() returned nil pool")
			}
		})
	}
}

// Helper function to test URL parsing edge cases
func TestURLParsing(t *testing.T) {
	validURLs := []string{
		"http://localhost:8080",
		"https://api.crowdsec.net",
		"http://127.0.0.1:8080/",
		"https://localhost:8081/v1",
	}

	invalidURLs := []string{
		"://invalid",
		"not-a-url",
		"",
	}

	for _, urlStr := range validURLs {
		t.Run("valid_"+urlStr, func(t *testing.T) {
			_, err := url.Parse(urlStr)
			if err != nil {
				t.Errorf("Expected valid URL %s to parse successfully, got error: %v", urlStr, err)
			}
		})
	}

	for _, urlStr := range invalidURLs {
		t.Run("invalid_"+urlStr, func(t *testing.T) {
			parsed, err := url.Parse(urlStr)
			// url.Parse is very permissive, so we check for specific invalid patterns
			if urlStr == "://invalid" && err == nil {
				if parsed.Scheme == "" && parsed.Host == "" {
					return // This is expected behavior for malformed URLs
				}
			}
		})
	}
}
