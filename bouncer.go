package csbouncer

import (
	"context"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// Bouncer provides both real-time decision checking and streaming capabilities
type Bouncer struct {
	config                 *Config
	apiClient              *apiclient.ApiClient
	tickerIntervalDuration time.Duration
	opts                   apiclient.DecisionsStreamOpts
	Stream                 chan *models.DecisionsStreamResponse
}

// NewBouncer creates a new Bouncer with the given configuration
func NewBouncer(config *Config) (*Bouncer, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}

	tickerDuration, err := config.GetTickerDuration()
	if err != nil {
		return nil, err
	}

	// Build stream options
	opts := apiclient.DecisionsStreamOpts{}
	if config.Scopes != nil {
		opts.Scopes = strings.Join(config.Scopes, ",")
	}
	if config.ScenariosContaining != nil {
		opts.ScenariosContaining = strings.Join(config.ScenariosContaining, ",")
	}
	if config.ScenariosNotContaining != nil {
		opts.ScenariosNotContaining = strings.Join(config.ScenariosNotContaining, ",")
	}
	if config.Origins != nil {
		opts.Origins = strings.Join(config.Origins, ",")
	}

	return &Bouncer{
		config:                 config,
		apiClient:              client,
		tickerIntervalDuration: tickerDuration,
		opts:                   opts,
		Stream:                 make(chan *models.DecisionsStreamResponse),
	}, nil
}

// NewBouncerFromFile creates a new Bouncer from a configuration file
func NewBouncerFromFile(configPath string) (*Bouncer, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	return NewBouncer(config)
}

// Get retrieves decisions for a given IP address (live mode)
func (b *Bouncer) Get(ctx context.Context, value string) (*models.GetDecisionsResponse, error) {
	filter := apiclient.DecisionsListOpts{
		IPEquals: value,
	}

	decision, resp, err := b.apiClient.Decisions.List(ctx, filter)
	if resp != nil && resp.Response != nil {
		resp.Response.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	return decision, nil
}

// StartStreaming starts the streaming bouncer that sends decisions to the Stream channel
func (b *Bouncer) StartStreaming(ctx context.Context) error {
	startup := true
	ticker := time.NewTicker(b.tickerIntervalDuration)
	defer ticker.Stop()

	// no delay for the first connection
	delay := time.After(0)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-delay:
		}

		b.opts.Startup = startup

		data, resp, err := b.getDecisionStream(ctx)
		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}

		if err != nil {
			if startup && b.config.RetryInitialConnect {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Second):
					continue
				}
			}

			if startup {
				// close the stream
				// this may cause the bouncer to exit
				close(b.Stream)
				return err
			}

			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case b.Stream <- data:
		}

		startup = false
		delay = ticker.C
	}
}

func (b *Bouncer) getDecisionStream(ctx context.Context) (*models.DecisionsStreamResponse, *apiclient.Response, error) {
	data, resp, err := b.apiClient.Decisions.GetStream(ctx, b.opts)

	TotalLAPICalls.Inc()

	if err != nil {
		TotalLAPIError.Inc()
	}

	return data, resp, err
}

// GetConfig returns the configuration used by this bouncer
func (b *Bouncer) GetConfig() *Config {
	return b.config
}

// GetMetricsInterval returns the metrics interval
func (b *Bouncer) GetMetricsInterval() time.Duration {
	return 15 * time.Minute // default metrics interval
}
