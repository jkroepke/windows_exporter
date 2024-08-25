//go:build windows

package diskdrive

import (
	"errors"
	"fmt"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/microsoft/wmi/pkg/constant"
	cim "github.com/microsoft/wmi/pkg/wmiinstance"
	"github.com/microsoft/wmi/server2019/root/cimv2"
	"github.com/prometheus-community/windows_exporter/pkg/types"
	"github.com/prometheus-community/windows_exporter/pkg/wmihelper"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	Name           = "diskdrive"
	win32DiskQuery = "SELECT DeviceID, Model, Caption, Name, Partitions, Size, Status, Availability FROM WIN32_DiskDrive"
)

type Config struct{}

var ConfigDefaults = Config{}

// A Collector is a Prometheus Collector for a few WMI metrics in Win32_DiskDrive.
type Collector struct {
	config Config

	wmiSession *cim.WmiSession

	availability *prometheus.Desc
	diskInfo     *prometheus.Desc
	partitions   *prometheus.Desc
	size         *prometheus.Desc
	status       *prometheus.Desc
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

	c.diskInfo = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "info"),
		"General drive information",
		[]string{
			"device_id",
			"model",
			"caption",
			"name",
		},
		nil,
	)
	c.status = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "status"),
		"Status of the drive",
		[]string{"name", "status"},
		nil,
	)
	c.size = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "size"),
		"Size of the disk drive. It is calculated by multiplying the total number of cylinders, tracks in each cylinder, sectors in each track, and bytes in each sector.",
		[]string{"name"},
		nil,
	)
	c.partitions = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "partitions"),
		"Number of partitions",
		[]string{"name"},
		nil,
	)
	c.availability = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "availability"),
		"Availability Status",
		[]string{"name", "availability"},
		nil,
	)

	return nil
}

var (
	allDiskStatus = []string{
		"OK",
		"Error",
		"Degraded",
		"Unknown",
		"Pred fail",
		"Starting",
		"Stopping",
		"Service",
		"Stressed",
		"Nonrecover",
		"No Contact",
		"Lost Comm",
	}

	availMap = map[int]string{
		1:  "Other",
		2:  "Unknown",
		3:  "Running / Full Power",
		4:  "Warning",
		5:  "In Test",
		6:  "Not Applicable",
		7:  "Power Off",
		8:  "Off line",
		9:  "Off Duty",
		10: "Degraded",
		11: "Not Installed",
		12: "Install Error",
		13: "Power Save - Unknown",
		14: "Power Save - Low Power Mode",
		15: "Power Save - Standby",
		16: "Power Cycle",
		17: "Power Save - Warning",
		18: "Paused",
		19: "Not Ready",
		20: "Not Configured",
		21: "Quiesced",
	}
)

// Collect sends the metric values for each metric to the provided prometheus Metric channel.
func (c *Collector) Collect(_ *types.ScrapeContext, logger log.Logger, ch chan<- prometheus.Metric) error {
	logger = log.With(logger, "collector", Name)
	if err := c.collect(logger, ch); err != nil {
		_ = level.Error(logger).Log("msg", "failed collecting disk_drive_info metrics", "err", err)
		return err
	}
	return nil
}

func (c *Collector) collect(logger log.Logger, ch chan<- prometheus.Metric) error {
	instances, err := c.wmiSession.EnumerateInstances("Win32_DiskDrive")
	if err != nil {
		return fmt.Errorf("failed to query instances: %w", err)
	}

	if len(instances) == 0 {
		return errors.New("WMI query returned empty result set")
	}

	defer wmihelper.CloseInstances(logger, instances)

	for _, diskInstance := range instances {
		disk, err := cimv2.NewWin32_DiskDriveEx1(diskInstance)
		if err != nil {
			return fmt.Errorf("failed to create Win32_DiskDrive instance: %w", err)
		}

		ch <- prometheus.MustNewConstMetric(
			c.diskInfo,
			prometheus.GaugeValue,
			1.0,
			strings.Trim(disk.DeviceID, "\\.\\"), //nolint:staticcheck
			strings.TrimRight(disk.Model, " "),
			strings.TrimRight(disk.Caption, " "),
			strings.TrimRight(disk.Name, "\\.\\"), //nolint:staticcheck
		)

		for _, status := range allDiskStatus {
			isCurrentState := 0.0
			if status == disk.Status {
				isCurrentState = 1.0
			}

			ch <- prometheus.MustNewConstMetric(
				c.status,
				prometheus.GaugeValue,
				isCurrentState,
				strings.Trim(disk.Name, "\\.\\"), //nolint:staticcheck
				status,
			)
		}

		ch <- prometheus.MustNewConstMetric(
			c.size,
			prometheus.GaugeValue,
			float64(disk.Size),
			strings.Trim(disk.Name, "\\.\\"), //nolint:staticcheck
		)

		ch <- prometheus.MustNewConstMetric(
			c.partitions,
			prometheus.GaugeValue,
			float64(disk.Partitions),
			strings.Trim(disk.Name, "\\.\\"), //nolint:staticcheck
		)

		for availNum, val := range availMap {
			isCurrentState := 0.0
			if availNum == int(disk.Availability) {
				isCurrentState = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.availability,
				prometheus.GaugeValue,
				isCurrentState,
				strings.Trim(disk.Name, "\\.\\"), //nolint:staticcheck
				val,
			)
		}
	}

	return nil
}
