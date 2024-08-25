package collector

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	cim "github.com/microsoft/wmi/pkg/wmiinstance"
	"github.com/prometheus-community/windows_exporter/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

type Collectors struct {
	collectors        Map
	perfCounterQuery  string
	wmiSessionManager *cim.WmiSessionManager
}

type (
	BuilderWithFlags[C Collector] func(*kingpin.Application) C
	Map                           map[string]Collector
)

// Collector interface that a collector has to implement.
type Collector interface {
	Build(logger log.Logger, wmiSessionManager *cim.WmiSessionManager) error
	// Close closes the collector
	Close() error
	// GetName get the name of the collector
	GetName() string
	// GetPerfCounter returns the perf counter required by the collector
	GetPerfCounter(logger log.Logger) ([]string, error)
	// Collect Get new metrics and expose them via prometheus registry.
	Collect(ctx *types.ScrapeContext, logger log.Logger, ch chan<- prometheus.Metric) (err error)
}
