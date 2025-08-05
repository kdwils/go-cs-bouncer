# Go CrowdSec Bouncer

`go-cs-bouncer` is a simple Go library for creating CrowdSec bouncers.

## Installation

```sh
go get -u github.com/crowdsecurity/go-cs-bouncer
```

## Quick Start

### Unified Bouncer (Both Live Queries and Streaming)

```go
package main

import (
    "context"
    "fmt"
    "log"

    csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func main() {
    // Create configuration
    config := &csbouncer.Config{
        APIKey: "your-api-key",
        APIUrl: "http://localhost:8080/",
        TickerInterval: "30s",
    }

    // Create bouncer (supports both live and streaming)
    bouncer, err := csbouncer.NewBouncer(config)
    if err != nil {
        log.Fatal(err)
    }

    // Live mode - query for decisions
    ipToQuery := "1.2.3.4"
    response, err := bouncer.Get(context.Background(), ipToQuery)
    if err != nil {
        log.Fatalf("unable to get decision for ip '%s': %s", ipToQuery, err)
    }

    if len(*response) == 0 {
        fmt.Printf("no decision for '%s'\n", ipToQuery)
    } else {
        for _, decision := range *response {
            fmt.Printf("Decision: IP: %s | Scenario: %s | Duration: %s | Scope: %s\n",
                *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
        }
    }

    // Streaming mode - get real-time updates
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Start streaming in a goroutine
    go func() {
        if err := bouncer.StartStream(ctx); err != nil {
            log.Printf("Streaming stopped: %v", err)
        }
        cancel()
    }()

    // Process decisions from the stream
    for streamDecision := range bouncer.Stream {
        for _, decision := range streamDecision.Deleted {
            fmt.Printf("Expired: IP: %s | Scenario: %s\n",
                *decision.Value, *decision.Scenario)
        }
        for _, decision := range streamDecision.New {
            fmt.Printf("New: IP: %s | Scenario: %s\n",
                *decision.Value, *decision.Scenario)
        }
    }
}
```

### Using Configuration Files

You can also load configuration from YAML files:

```go
// Create bouncer from config file
bouncer, err := csbouncer.NewBouncerFromFile("./config.yaml")
if err != nil {
    log.Fatal(err)
}

// Use for live queries
decisions, err := bouncer.Get(ctx, "1.2.3.4")

// Or start streaming
go bouncer.StartStream(ctx)
for decision := range bouncer.Stream {
    // Process decisions
}
```

Example `config.yaml`:

```yaml
api_url: http://localhost:8080/
api_key: your-api-key-here
update_frequency: 30s
origins:
  - CAPI
scenarios_containing:
  - ssh
```

### TLS/mTLS Configuration

```go
config := &csbouncer.Config{
    APIUrl:             "https://localhost:8081/",
    CertPath:           "/path/to/cert.pem",
    KeyPath:            "/path/to/key.pem",
    CAPath:             "/path/to/ca.pem",
    InsecureSkipVerify: &[]bool{true}[0], // Use pointer to bool
}

bouncer, err := csbouncer.NewBouncer(config)
```

## API Reference

### Core Types

#### Bouncer
The main struct that provides both live queries and streaming capabilities.

```go
type Bouncer struct {
    // Private fields
}

// Create new bouncer
func NewBouncer(config *Config) (*Bouncer, error)
func NewBouncerFromFile(configPath string) (*Bouncer, error)

// Live queries
func (b *Bouncer) Get(ctx context.Context, value string) (*models.GetDecisionsResponse, error)

// Streaming
func (b *Bouncer) StartStream(ctx context.Context) error
func (b *Bouncer) Stream chan *models.DecisionsStreamResponse

// Configuration
func (b *Bouncer) GetConfig() *Config
func (b *Bouncer) GetMetricsInterval() time.Duration
```

## Configuration Options

| Field | Type | Description |
|-------|------|-------------|
| `APIKey` | `string` | API key for authentication |
| `APIUrl` | `string` | CrowdSec LAPI URL |
| `CertPath` | `string` | Path to client certificate (for mTLS) |
| `KeyPath` | `string` | Path to client private key (for mTLS) |
| `CAPath` | `string` | Path to CA certificate |
| `InsecureSkipVerify` | `*bool` | Skip TLS certificate verification |
| `RetryInitialConnect` | `bool` | Retry on initial connection failure |
| `TickerInterval` | `string` | Update frequency for streaming (default: "10s") |
| `Scopes` | `[]string` | Decision scopes to filter |
| `ScenariosContaining` | `[]string` | Filter scenarios containing these strings |
| `ScenariosNotContaining` | `[]string` | Filter scenarios not containing these strings |
| `Origins` | `[]string` | Decision origins to filter |
| `UserAgent` | `string` | Custom user agent string (default: "go-cs-bouncer") |

## Error Handling

The library uses standard Go error handling patterns:

```go
bouncer, err := csbouncer.NewBouncer(config)
if err != nil {
    // Handle configuration or initialization error
    log.Fatal(err)
}

response, err := bouncer.Get(ctx, "1.2.3.4")
if err != nil {
    // Handle API call error
    log.Printf("API error: %v", err)
    return
}
```

## Usage Patterns

### Live Query Only
```go
bouncer, _ := csbouncer.NewBouncer(config)
decisions, err := bouncer.Get(ctx, "1.2.3.4")
// Process decisions...
```

### Streaming Only
```go
bouncer, _ := csbouncer.NewBouncer(config)
go bouncer.StartStream(ctx)
for decision := range bouncer.Stream {
    // Process streaming decisions...
}
```

### Combined Live + Streaming
```go
bouncer, _ := csbouncer.NewBouncer(config)

// Use live queries when needed
decisions, _ := bouncer.Get(ctx, "1.2.3.4")

// Also start streaming for real-time updates
go bouncer.StartStream(ctx)
for decision := range bouncer.Stream {
    // Process streaming decisions...
}
```

## Decision Structure

Decisions returned by the API have the following structure:

```go
type Decision struct {
    Duration  *string `json:"duration"`   // Duration of the decision
    Origin    *string `json:"origin"`     // Origin: cscli, crowdsec, etc.
    Scenario  *string `json:"scenario"`   // Scenario that triggered the decision
    Scope     *string `json:"scope"`      // Scope: IP, range, username, etc.
    Type      *string `json:"type"`       // Type: ban, captcha, etc.
    Value     *string `json:"value"`      // The actual value (IP, range, etc.)
    ID        int64   `json:"id"`         // Decision ID
    StartIP   int64   `json:"start_ip"`   // Start IP (for ranges)
    EndIP     int64   `json:"end_ip"`     // End IP (for ranges)
}
```