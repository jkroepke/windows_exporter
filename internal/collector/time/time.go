// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package time

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Microsoft/hcsshim/osversion"
	"github.com/alecthomas/kingpin/v2"
	"github.com/beevik/ntp"
	"github.com/prometheus-community/windows_exporter/internal/headers/kernel32"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/pdh"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	Name = "time"

	collectorSystemTime = "system_time"
	collectorW32Time    = "w32time"
	collectorNTPClient  = "ntp_client"
)

type Config struct {
	CollectorsEnabled []string `yaml:"collectors_enabled"`
	NTPServer         string   `yaml:"ntp_server"`
}

//nolint:gochecknoglobals
var ConfigDefaults = Config{
	CollectorsEnabled: []string{
		collectorSystemTime,
		collectorW32Time,
		collectorNTPClient,
	},
	NTPServer: "",
}

// Collector is a Prometheus Collector for Perflib counter metrics.
type Collector struct {
	config Config

	perfDataCollector *pdh.Collector
	perfDataObject    []perfDataCounterValues

	ppbCounterPresent bool

	currentTime                     *prometheus.Desc
	timezone                        *prometheus.Desc
	clockFrequencyAdjustment        *prometheus.Desc
	clockFrequencyAdjustmentPPB     *prometheus.Desc
	computedTimeOffset              *prometheus.Desc
	ntpClientTimeSourceCount        *prometheus.Desc
	ntpRoundTripDelay               *prometheus.Desc
	ntpServerIncomingRequestsTotal  *prometheus.Desc
	ntpServerOutgoingResponsesTotal *prometheus.Desc
	ntpServerResponseRTT            *prometheus.Desc
	ntpClockOffset                  *prometheus.Desc
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	if config.CollectorsEnabled == nil {
		config.CollectorsEnabled = ConfigDefaults.CollectorsEnabled
	}

	if config.NTPServer == "" {
		config.NTPServer = ConfigDefaults.NTPServer
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
	c.config.CollectorsEnabled = make([]string, 0)

	var collectorsEnabled string

	app.Flag(
		"collector.time.enabled",
		"Comma-separated list of collectors to use. Defaults to all, if not specified. ntp may not available on all systems.",
	).Default(strings.Join(ConfigDefaults.CollectorsEnabled, ",")).StringVar(&collectorsEnabled)

	app.Flag(
		"collector.time.ntp-server",
		"NTP server to used by ntp_client sub collector to identify a click screw. If not specified, the systems NTP server is used.",
	).Default("").StringVar(&c.config.NTPServer)

	app.Action(func(*kingpin.ParseContext) error {
		c.config.CollectorsEnabled = strings.Split(collectorsEnabled, ",")

		return nil
	})

	return c
}

func (c *Collector) GetName() string {
	return Name
}

func (c *Collector) Close() error {
	if slices.Contains(c.config.CollectorsEnabled, collectorW32Time) {
		c.perfDataCollector.Close()
	}

	return nil
}

func (c *Collector) Build(_ *slog.Logger, _ *mi.Session) error {
	for _, collector := range c.config.CollectorsEnabled {
		if !slices.Contains(ConfigDefaults.CollectorsEnabled, collector) {
			return fmt.Errorf("unknown collector: %s", collector)
		}
	}

	// https://github.com/prometheus-community/windows_exporter/issues/1891
	c.ppbCounterPresent = osversion.Build() >= osversion.LTSC2019

	c.currentTime = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "current_timestamp_seconds"),
		"OperatingSystem.LocalDateTime",
		nil,
		nil,
	)
	c.timezone = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "timezone"),
		"OperatingSystem.LocalDateTime",
		[]string{"timezone"},
		nil,
	)
	c.clockFrequencyAdjustment = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "clock_frequency_adjustment"),
		"This value reflects the adjustment made to the local system clock frequency by W32Time in nominal clock units. This counter helps visualize the finer adjustments being made by W32time to synchronize the local clock.",
		nil,
		nil,
	)
	c.clockFrequencyAdjustmentPPB = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "clock_frequency_adjustment_ppb"),
		"This value reflects the adjustment made to the local system clock frequency by W32Time in Parts Per Billion (PPB) units. 1 PPB adjustment imples the system clock was adjusted at a rate of 1 nanosecond per second. The smallest possible adjustment can vary and can be expected to be in the order of 100&apos;s of PPB. This counter helps visualize the finer actions being taken by W32time to synchronize the local clock.",
		nil,
		nil,
	)
	c.computedTimeOffset = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "computed_time_offset_seconds"),
		"Absolute time offset between the system clock and the chosen time source, in seconds",
		nil,
		nil,
	)
	c.ntpClientTimeSourceCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "ntp_client_time_sources"),
		"Active number of NTP Time sources being used by the client",
		nil,
		nil,
	)
	c.ntpRoundTripDelay = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "ntp_round_trip_delay_seconds"),
		"Roundtrip delay experienced by the NTP client in receiving a response from the server for the most recent request, in seconds",
		nil,
		nil,
	)
	c.ntpServerOutgoingResponsesTotal = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "ntp_server_outgoing_responses_total"),
		"Total number of requests responded to by NTP server",
		nil,
		nil,
	)
	c.ntpServerIncomingRequestsTotal = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "ntp_server_incoming_requests_total"),
		"Total number of requests received by NTP server",
		nil,
		nil,
	)
	c.ntpServerResponseRTT = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "ntp_server_rtt_seconds"),
		"Response time of the NTP server in seconds",
		nil,
		nil,
	)
	c.ntpClockOffset = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "ntp_server_clock_offset_seconds"),
		"Clock offset of the NTP server in seconds",
		nil,
		nil,
	)

	var err error

	if slices.Contains(c.config.CollectorsEnabled, collectorW32Time) {
		c.perfDataCollector, err = pdh.NewCollector[perfDataCounterValues](pdh.CounterTypeRaw, "Windows Time Service", nil)
		if err != nil {
			return fmt.Errorf("failed to create Windows Time Service collector: %w", err)
		}
	}

	if c.config.NTPServer == "" {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\W32Time\Parameters`,
			registry.QUERY_VALUE)
		if err != nil {
			return fmt.Errorf("failed to detect systems NTP server: failed to open registry key: %w", err)
		}

		defer key.Close()

		ntpServer, _, err := key.GetStringValue("NtpServer")
		if err != nil {
			return fmt.Errorf("failed to detect systems NTP server: failed to get NtpServer value: %w", err)
		}

		c.config.NTPServer = ntpServer
	}

	return nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *Collector) Collect(ch chan<- prometheus.Metric) error {
	errs := make([]error, 0)

	if slices.Contains(c.config.CollectorsEnabled, collectorSystemTime) {
		if err := c.collectTime(ch); err != nil {
			errs = append(errs, fmt.Errorf("failed collecting time/%s metrics: %w", collectorSystemTime, err))
		}
	}

	if slices.Contains(c.config.CollectorsEnabled, collectorW32Time) {
		if err := c.collectW32Time(ch); err != nil {
			errs = append(errs, fmt.Errorf("failed collecting time/%s metrics: %w", collectorW32Time, err))
		}
	}

	if slices.Contains(c.config.CollectorsEnabled, collectorNTPClient) {
		if err := c.collectNTP(ch); err != nil {
			errs = append(errs, fmt.Errorf("failed collecting time/%s metrics: %w", collectorNTPClient, err))
		}
	}

	return errors.Join(errs...)
}

func (c *Collector) collectTime(ch chan<- prometheus.Metric) error {
	ch <- prometheus.MustNewConstMetric(
		c.currentTime,
		prometheus.GaugeValue,
		float64(time.Now().Unix()),
	)

	timeZoneInfo, err := kernel32.GetDynamicTimeZoneInformation()
	if err != nil {
		return err
	}

	// timeZoneKeyName contains the english name of the timezone.
	timezoneName := windows.UTF16ToString(timeZoneInfo.TimeZoneKeyName[:])

	ch <- prometheus.MustNewConstMetric(
		c.timezone,
		prometheus.GaugeValue,
		1.0,
		timezoneName,
	)

	return nil
}

func (c *Collector) collectW32Time(ch chan<- prometheus.Metric) error {
	err := c.perfDataCollector.Collect(&c.perfDataObject)
	if err != nil {
		return fmt.Errorf("failed to collect time metrics: %w", err)
	}

	ch <- prometheus.MustNewConstMetric(
		c.clockFrequencyAdjustment,
		prometheus.GaugeValue,
		c.perfDataObject[0].ClockFrequencyAdjustment,
	)

	if c.ppbCounterPresent {
		ch <- prometheus.MustNewConstMetric(
			c.clockFrequencyAdjustmentPPB,
			prometheus.GaugeValue,
			c.perfDataObject[0].ClockFrequencyAdjustmentPPB,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.computedTimeOffset,
		prometheus.GaugeValue,
		c.perfDataObject[0].ComputedTimeOffset/1000000, // microseconds -> seconds
	)
	ch <- prometheus.MustNewConstMetric(
		c.ntpClientTimeSourceCount,
		prometheus.GaugeValue,
		c.perfDataObject[0].NTPClientTimeSourceCount,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ntpRoundTripDelay,
		prometheus.GaugeValue,
		c.perfDataObject[0].NTPRoundTripDelay/1000000, // microseconds -> seconds
	)
	ch <- prometheus.MustNewConstMetric(
		c.ntpServerIncomingRequestsTotal,
		prometheus.CounterValue,
		c.perfDataObject[0].NTPServerIncomingRequestsTotal,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ntpServerOutgoingResponsesTotal,
		prometheus.CounterValue,
		c.perfDataObject[0].NTPServerOutgoingResponsesTotal,
	)

	return nil
}

func (c *Collector) collectNTP(ch chan<- prometheus.Metric) error {
	response, err := ntp.QueryWithOptions(c.config.NTPServer, ntp.QueryOptions{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to query NTP server %s: %w", c.config.NTPServer, err)
	}

	if err = response.Validate(); err != nil {
		return fmt.Errorf("failed to validate NTP response from server %s: %w", c.config.NTPServer, err)
	}

	ch <- prometheus.MustNewConstMetric(
		c.ntpClockOffset,
		prometheus.GaugeValue,
		response.ClockOffset.Seconds(),
	)

	ch <- prometheus.MustNewConstMetric(
		c.ntpServerResponseRTT,
		prometheus.GaugeValue,
		response.RTT.Seconds(),
	)

	return nil
}
