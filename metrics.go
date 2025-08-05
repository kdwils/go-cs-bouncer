package csbouncer

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/version"
)

// MetricsUpdater is a function type for updating metrics
type MetricsUpdater func(*models.RemediationComponentsMetrics, time.Duration)

const defaultMetricsInterval = 15 * time.Minute

// MetricsProvider handles usage metrics reporting to CrowdSec LAPI
type MetricsProvider struct {
	APIClient *apiclient.ApiClient
	Interval  time.Duration
	static    staticMetrics
	updater   MetricsUpdater
}

type staticMetrics struct {
	osName       string
	osVersion    string
	startupTS    int64
	featureFlags []string
	bouncerType  string
}

// newStaticMetrics creates static metrics for a bouncer type
func newStaticMetrics(bouncerType string) staticMetrics {
	osName, osVersion := version.DetectOS()

	return staticMetrics{
		osName:       osName,
		osVersion:    osVersion,
		startupTS:    time.Now().Unix(),
		featureFlags: []string{},
		bouncerType:  bouncerType,
	}
}

// NewMetricsProvider creates a new metrics provider
func NewMetricsProvider(client *apiclient.ApiClient, bouncerType string, updater MetricsUpdater) *MetricsProvider {
	return &MetricsProvider{
		APIClient: client,
		Interval:  defaultMetricsInterval,
		updater:   updater,
		static:    newStaticMetrics(bouncerType),
	}
}

func (m *MetricsProvider) metricsPayload() *models.AllMetrics {
	os := &models.OSversion{
		Name:    &m.static.osName,
		Version: &m.static.osVersion,
	}

	bouncerVersion := version.String()

	base := &models.BaseMetrics{
		Os:                  os,
		Version:             &bouncerVersion,
		FeatureFlags:        m.static.featureFlags,
		Metrics:             make([]*models.DetailedMetrics, 0),
		UtcStartupTimestamp: &m.static.startupTS,
	}

	item0 := &models.RemediationComponentsMetrics{
		BaseMetrics: *base,
		Type:        m.static.bouncerType,
	}

	if m.updater != nil {
		m.updater(item0, m.Interval)
	}

	return &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{item0},
	}
}

func (m *MetricsProvider) sendMetrics(ctx context.Context) error {
	ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	met := m.metricsPayload()

	_, resp, err := m.APIClient.UsageMetrics.Add(ctxTime, met)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("timeout sending metrics")
	case resp != nil && resp.Response != nil && resp.Response.StatusCode == http.StatusNotFound:
		return errors.New("metrics endpoint not found, older LAPI?")
	case err != nil:
		return err
	case resp.Response.StatusCode != http.StatusCreated:
		return errors.New("failed to send metrics: " + resp.Response.Status)
	default:
		return nil // success
	}
}

// Run starts the metrics provider in a loop
func (m *MetricsProvider) Run(ctx context.Context) error {
	if m.Interval == 0 {
		return nil // metrics disabled
	}

	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = m.sendMetrics(ctx) // ignore errors for non-blocking operation
		}
	}
}
