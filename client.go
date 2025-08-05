package csbouncer

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

// NewClient creates a new API client based on the configuration
func NewClient(config *Config) (*apiclient.ApiClient, error) {
	if config.APIKey == "" && config.CertPath == "" && config.KeyPath == "" {
		return nil, errors.New("no API key nor certificate provided")
	}

	if config.APIKey != "" && (config.CertPath != "" || config.KeyPath != "") {
		return nil, errors.New("cannot use both API key and certificate auth")
	}

	apiURL, err := url.Parse(config.APIUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL '%s': %w", config.APIUrl, err)
	}

	insecureSkipVerify := config.InsecureSkipVerify != nil && *config.InsecureSkipVerify

	var httpClient *http.Client

	if config.APIKey != "" {
		httpClient, err = buildAPIKeyClient(config.APIKey, config.CAPath, insecureSkipVerify, apiURL.Scheme == "https")
	} else {
		httpClient, err = buildCertClient(config.CertPath, config.KeyPath, config.CAPath, insecureSkipVerify)
	}

	if err != nil {
		return nil, err
	}

	return apiclient.NewDefaultClient(apiURL, "v1", config.UserAgent, httpClient)
}

func buildAPIKeyClient(apiKey, caPath string, insecureSkipVerify, isHTTPS bool) (*http.Client, error) {
	transport := &apiclient.APIKeyTransport{
		APIKey: apiKey,
	}

	if isHTTPS {
		caCertPool, err := getCertPool(caPath)
		if err != nil {
			return nil, err
		}

		transport.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: insecureSkipVerify,
			},
		}
	}

	return transport.Client(), nil
}

func buildCertClient(certPath, keyPath, caPath string, insecureSkipVerify bool) (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load certificate '%s' and key '%s': %w", certPath, keyPath, err)
	}

	caCertPool, err := getCertPool(caPath)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{certificate},
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}, nil
}

// getCertPool creates a certificate pool with system certificates and optional CA
func getCertPool(caPath string) (*x509.CertPool, error) {
	cp, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to load system CA certificates: %w", err)
	}

	if cp == nil {
		cp = x509.NewCertPool()
	}

	if caPath == "" {
		return cp, nil
	}

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load CA certificate '%s': %w", caPath, err)
	}

	cp.AppendCertsFromPEM(caCert)
	return cp, nil
}
