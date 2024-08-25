//go:build windows

package logon

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	cim "github.com/microsoft/wmi/pkg/wmiinstance"
	"github.com/prometheus-community/windows_exporter/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

const Name = "logon"

type Config struct{}

var ConfigDefaults = Config{}

// A Collector is a Prometheus Collector for WMI metrics.
type Collector struct {
	config Config

	wmiSession *cim.WmiSession

	logonType *prometheus.Desc
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	c := &Collector{
		config: *config,
	}

	return c
}

func NewWithFlags(_ *kingpin.Application) *Collector {
	return &Collector{}
}

func (c *Collector) GetName() string {
	return Name
}

func (c *Collector) GetPerfCounter(_ log.Logger) ([]string, error) {
	return []string{}, nil
}

func (c *Collector) Close() error {
	if c.wmiSession != nil {
		c.wmiSession.Dispose()
	}

	return nil
}

func (c *Collector) Build(_ log.Logger, sessionManager *cim.WmiSessionManager) error {
	wmiSession, err := sessionManager.GetLocalSession("ROOT\\CimV2")
	if err != nil {
		return fmt.Errorf("failed to connect to WMI: %w", err)
	}

	connected, err := wmiSession.Connect()
	if !connected || err != nil {
		return fmt.Errorf("failed to connect to WMI: %w", err)
	}

	c.wmiSession = wmiSession

	c.logonType = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "logon_type"),
		"Number of active logon sessions (LogonSession.LogonType)",
		[]string{"status"},
		nil,
	)
	return nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *Collector) Collect(_ *types.ScrapeContext, logger log.Logger, ch chan<- prometheus.Metric) error {
	logger = log.With(logger, "collector", Name)
	if err := c.collect(logger, ch); err != nil {
		_ = level.Error(logger).Log("msg", "failed collecting user metrics", "err", err)
		return err
	}
	return nil
}

func (c *Collector) collect(logger log.Logger, ch chan<- prometheus.Metric) error {
	// Win32_LogonSession docs:
	// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession
	// https://wutils.com/wmi/root/cimv2/win32_logonsession/

	logonSessionInstances, err := c.wmiSession.QueryInstances("SELECT LogonType FROM Win32_LogonSession")
	if err != nil {
		return fmt.Errorf("failed to query WMI: %v", err)
	}

	defer func() {
		for _, instance := range logonSessionInstances {
			if err := instance.Close(); err != nil {
				_ = level.Warn(logger).Log("msg", "failed to close WMI instance", "err", err)
			}
		}
	}()

	if len(logonSessionInstances) == 0 {
		return fmt.Errorf("no Win32_Processor instances found")
	}

	// Init counters
	var (
		system                  int
		interactive             int
		network                 int
		batch                   int
		service                 int
		proxy                   int
		unlock                  int
		networkClearText        int
		newCredentials          int
		remoteInteractive       int
		cachedInteractive       int
		cachedRemoteInterActive int
		cachedUnlock            int
	)

	for _, instance := range logonSessionInstances {
		propertyLogonType, err := instance.GetProperty("LogonType")
		if err != nil {
			return fmt.Errorf("failed to get LogonType property: %w", err)
		}

		logonType, ok := propertyLogonType.(uint32)
		if !ok {
			return fmt.Errorf("failed to cast LogonType to uint32: %v", propertyLogonType)
		}

		switch logonType {
		case 0:
			system++
		case 2:
			interactive++
		case 3:
			network++
		case 4:
			batch++
		case 5:
			service++
		case 6:
			proxy++
		case 7:
			unlock++
		case 8:
			networkClearText++
		case 9:
			newCredentials++
		case 10:
			remoteInteractive++
		case 11:
			cachedInteractive++
		case 12:
			cachedRemoteInterActive++
		case 13:
			cachedUnlock++
		}
	}

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(system),
		"system",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(interactive),
		"interactive",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(network),
		"network",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(batch),
		"batch",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(service),
		"service",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(proxy),
		"proxy",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(unlock),
		"unlock",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(networkClearText),
		"network_clear_text",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(newCredentials),
		"new_credentials",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(remoteInteractive),
		"remote_interactive",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(cachedInteractive),
		"cached_interactive",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(remoteInteractive),
		"cached_remote_interactive",
	)

	ch <- prometheus.MustNewConstMetric(
		c.logonType,
		prometheus.GaugeValue,
		float64(cachedUnlock),
		"cached_unlock",
	)

	return nil
}
