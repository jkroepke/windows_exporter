//go:build windows

package cpu_info

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/microsoft/wmi/pkg/constant"
	cim "github.com/microsoft/wmi/pkg/wmiinstance"
	"github.com/prometheus-community/windows_exporter/pkg/types"
	"github.com/prometheus-community/windows_exporter/pkg/wmihelper"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	Name = "cpu_info"
)

type Config struct{}

var ConfigDefaults = Config{}

// A Collector is a Prometheus Collector for a few WMI metrics in Win32_Processor.
type Collector struct {
	config Config

	wmiSession *cim.WmiSession

	cpuInfo *prometheus.Desc
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
	var err error

	if c.wmiSession, err = wmihelper.OpenSession(sessionManager, string(constant.CimV2)); err != nil {
		return fmt.Errorf("failed to open WMI session: %w", err)
	}

	c.cpuInfo = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", Name),
		"Labelled CPU information as provided by Win32_Processor",
		[]string{
			"architecture",
			"device_id",
			"description",
			"family",
			"l2_cache_size",
			"l3_cache_size",
			"name",
		},
		nil,
	)

	return nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *Collector) Collect(_ *types.ScrapeContext, logger log.Logger, ch chan<- prometheus.Metric) error {
	logger = log.With(logger, "collector", Name)
	if err := c.collect(logger, ch); err != nil {
		_ = level.Error(logger).Log("msg", "failed collecting cpu_info metrics", "err", err)
		return err
	}
	return nil
}

type win32Processor struct {
	Architecture uint32
	DeviceID     string
	Description  string
	Family       uint16
	L2CacheSize  uint32
	L3CacheSize  uint32
	Name         string
}

func (c *Collector) collect(logger log.Logger, ch chan<- prometheus.Metric) error {
	var dst []win32Processor
	if err := wmihelper.QueryAll(logger, c.wmiSession, "Win32_Processor", &dst); err != nil {
		return fmt.Errorf("WMI query failed: %w", err)
	}
	if len(dst) == 0 {
		return errors.New("WMI query returned empty result set")
	}

	// Some CPUs end up exposing trailing spaces for certain strings, so clean them up
	for _, processor := range dst {
		ch <- prometheus.MustNewConstMetric(
			c.cpuInfo,
			prometheus.GaugeValue,
			1.0,
			strconv.Itoa(int(processor.Architecture)),
			strings.TrimRight(processor.DeviceID, " "),
			strings.TrimRight(processor.Description, " "),
			strconv.Itoa(int(processor.Family)),
			strconv.Itoa(int(processor.L2CacheSize)),
			strconv.Itoa(int(processor.L3CacheSize)),
			strings.TrimRight(processor.Name, " "),
		)
	}

	return nil
}
