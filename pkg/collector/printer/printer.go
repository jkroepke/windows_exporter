//go:build windows

package printer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	cim "github.com/microsoft/wmi/pkg/wmiinstance"
	"github.com/microsoft/wmi/server2019/root/cimv2"
	"github.com/prometheus-community/windows_exporter/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

const Name = "printer"

// printerStatusMap source: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-printer#:~:text=Power%20Save-,PrinterStatus,Offline%20(7),-PrintJobDataType
var printerStatusMap = map[uint16]string{
	1: "Other",
	2: "Unknown",
	3: "Idle",
	4: "Printing",
	5: "Warmup",
	6: "Stopped Printing",
	7: "Offline",
}

type Config struct {
	PrinterInclude *regexp.Regexp `yaml:"printer_include"`
	PrinterExclude *regexp.Regexp `yaml:"printer_exclude"`
}

var ConfigDefaults = Config{
	PrinterInclude: types.RegExpAny,
	PrinterExclude: types.RegExpEmpty,
}

type Collector struct {
	config Config

	wmiSession *cim.WmiSession

	printerStatus    *prometheus.Desc
	printerJobStatus *prometheus.Desc
	printerJobCount  *prometheus.Desc
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	if config.PrinterExclude == nil {
		config.PrinterExclude = ConfigDefaults.PrinterExclude
	}

	if config.PrinterInclude == nil {
		config.PrinterInclude = ConfigDefaults.PrinterInclude
	}

	c := &Collector{
		config: *config,
	}

	return c
}

func NewWithFlags(app *kingpin.Application) *Collector {
	c := &Collector{
		config: ConfigDefaults,
	}

	var printerInclude, printerExclude string

	app.Flag(
		"collector.printer.include",
		"Regular expression to match printers to collect metrics for",
	).Default(c.config.PrinterInclude.String()).StringVar(&printerInclude)

	app.Flag(
		"collector.printer.exclude",
		"Regular expression to match printers to exclude",
	).Default(c.config.PrinterExclude.String()).StringVar(&printerExclude)

	app.Action(func(*kingpin.ParseContext) error {
		var err error

		c.config.PrinterInclude, err = regexp.Compile(fmt.Sprintf("^(?:%s)$", printerInclude))
		if err != nil {
			return fmt.Errorf("collector.printer.include: %w", err)
		}

		c.config.PrinterExclude, err = regexp.Compile(fmt.Sprintf("^(?:%s)$", printerExclude))
		if err != nil {
			return fmt.Errorf("collector.printer.exclude: %w", err)
		}

		return nil
	})

	return c
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
	c.printerJobStatus = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "job_status"),
		"A counter of printer jobs by status",
		[]string{"printer", "status"},
		nil,
	)
	c.printerStatus = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "status"),
		"Printer status",
		[]string{"printer", "status"},
		nil,
	)
	c.printerJobCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "job_count"),
		"Number of jobs processed by the printer since the last reset",
		[]string{"printer"},
		nil,
	)

	return nil
}

func (c *Collector) GetName() string { return Name }

func (c *Collector) GetPerfCounter(_ log.Logger) ([]string, error) { return []string{"Printer"}, nil }

func (c *Collector) Collect(_ *types.ScrapeContext, logger log.Logger, ch chan<- prometheus.Metric) error {
	logger = log.With(logger, "collector", Name)
	if err := c.collectPrinterStatus(logger, ch); err != nil {
		_ = level.Error(logger).Log("msg", "failed to collect printer status metrics", "err", err)
		return err
	}

	if err := c.collectPrinterJobStatus(logger, ch); err != nil {
		_ = level.Error(logger).Log("msg", "failed to collect printer job status metrics", "err", err)
		return err
	}

	return nil
}

func (c *Collector) collectPrinterStatus(logger log.Logger, ch chan<- prometheus.Metric) error {
	win32PrinterInstances, err := c.wmiSession.EnumerateInstances("Win32_Printer")
	if err != nil {
		return fmt.Errorf("failed to query WMI: %v", err)
	}

	defer func() {
		for _, instance := range win32PrinterInstances {
			if err := instance.Close(); err != nil {
				_ = level.Warn(logger).Log("msg", "failed to close WMI instance", "err", err)
			}
		}
	}()

	for _, printerInstance := range win32PrinterInstances {
		printer, err := cimv2.NewWin32_PrinterEx1(printerInstance)
		if err != nil {
			return fmt.Errorf("failed to parse Win32_Printer: %w", err)
		}

		if c.config.PrinterExclude.MatchString(printer.Name) ||
			!c.config.PrinterInclude.MatchString(printer.Name) {
			continue
		}

		for printerStatus, printerStatusName := range printerStatusMap {
			isCurrentStatus := 0.0
			if printerStatus == printer.PrinterStatus {
				isCurrentStatus = 1.0
			}

			ch <- prometheus.MustNewConstMetric(
				c.printerStatus,
				prometheus.GaugeValue,
				isCurrentStatus,
				printer.Name,
				printerStatusName,
			)
		}

		ch <- prometheus.MustNewConstMetric(
			c.printerJobCount,
			prometheus.CounterValue,
			float64(printer.JobCountSinceLastReset),
			printer.Name,
		)
	}

	return nil
}

func (c *Collector) collectPrinterJobStatus(logger log.Logger, ch chan<- prometheus.Metric) error {
	win32PrintJobInstances, err := c.wmiSession.EnumerateInstances("Win32_PrintJob")
	if err != nil {
		return fmt.Errorf("failed to query WMI: %v", err)
	}

	defer func() {
		for _, instance := range win32PrintJobInstances {
			if err := instance.Close(); err != nil {
				_ = level.Warn(logger).Log("msg", "failed to close WMI instance", "err", err)
			}
		}
	}()

	groupedPrintJobs, err := c.groupPrintJobs(win32PrintJobInstances)
	if err != nil {
		return fmt.Errorf("failed to group print jobs: %w", err)
	}

	for group, count := range groupedPrintJobs {
		ch <- prometheus.MustNewConstMetric(
			c.printerJobStatus,
			prometheus.GaugeValue,
			float64(count),
			group.printerName,
			group.status,
		)
	}

	return nil
}

type PrintJobStatusGroup struct {
	printerName string
	status      string
}

func (c *Collector) groupPrintJobs(win32PrintJobInstances []*cim.WmiInstance) (map[PrintJobStatusGroup]int, error) {
	groupedPrintJobs := make(map[PrintJobStatusGroup]int)

	for _, printJobInstance := range win32PrintJobInstances {
		printJob, err := cimv2.NewWin32_PrintJobEx1(printJobInstance)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Win32_PrintJob: %w", err)
		}

		printerName := strings.Split(printJob.Name, ",")[0]
		if c.config.PrinterExclude.MatchString(printerName) ||
			!c.config.PrinterInclude.MatchString(printerName) {
			continue
		}

		groupedPrintJobs[PrintJobStatusGroup{
			printerName: printerName,
			status:      printJob.Status,
		}]++
	}

	return groupedPrintJobs, nil
}
