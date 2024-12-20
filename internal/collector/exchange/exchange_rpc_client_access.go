// Copyright 2024 The Prometheus Authors
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

package exchange

import (
	"fmt"

	"github.com/prometheus-community/windows_exporter/internal/perfdata"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	rpcAveragedLatency = "RPC Averaged Latency"
	rpcRequests        = "RPC Requests"
	// activeUserCount    = "Active User Count"
	connectionCount     = "Connection Count"
	rpcOperationsPerSec = "RPC Operations/sec"
	userCount           = "User Count"
)

func (c *Collector) buildRPC() error {
	counters := []string{
		rpcAveragedLatency,
		rpcRequests,
		activeUserCount,
		connectionCount,
		rpcOperationsPerSec,
		userCount,
	}

	var err error

	c.perfDataCollectorRpcClientAccess, err = perfdata.NewCollector("MSExchange RpcClientAccess", perfdata.InstancesAll, counters)
	if err != nil {
		return fmt.Errorf("failed to create MSExchange RpcClientAccess collector: %w", err)
	}

	c.rpcAveragedLatency = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "rpc_avg_latency_sec"),
		"The latency (sec) averaged for the past 1024 packets",
		nil,
		nil,
	)
	c.rpcRequests = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "rpc_requests"),
		"Number of client requests currently being processed by the RPC Client Access service",
		nil,
		nil,
	)
	c.activeUserCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "rpc_active_user_count"),
		"Number of unique users that have shown some kind of activity in the last 2 minutes",
		nil,
		nil,
	)
	c.connectionCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "rpc_connection_count"),
		"Total number of client connections maintained",
		nil,
		nil,
	)
	c.rpcOperationsPerSec = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "rpc_operations_total"),
		"The rate at which RPC operations occur",
		nil,
		nil,
	)
	c.userCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "rpc_user_count"),
		"Number of users",
		nil,
		nil,
	)

	return nil
}

func (c *Collector) collectRPC(ch chan<- prometheus.Metric) error {
	perfData, err := c.perfDataCollectorRpcClientAccess.Collect()
	if err != nil {
		return fmt.Errorf("failed to collect MSExchange RpcClientAccess: %w", err)
	}

	if len(perfData) == 0 {
		return fmt.Errorf("failed to collect MSExchange RpcClientAccess metrics: %w", types.ErrNoData)
	}

	for _, data := range perfData {
		ch <- prometheus.MustNewConstMetric(
			c.rpcAveragedLatency,
			prometheus.GaugeValue,
			c.msToSec(data[rpcAveragedLatency].FirstValue),
		)
		ch <- prometheus.MustNewConstMetric(
			c.rpcRequests,
			prometheus.GaugeValue,
			data[rpcRequests].FirstValue,
		)
		ch <- prometheus.MustNewConstMetric(
			c.activeUserCount,
			prometheus.GaugeValue,
			data[activeUserCount].FirstValue,
		)
		ch <- prometheus.MustNewConstMetric(
			c.connectionCount,
			prometheus.GaugeValue,
			data[connectionCount].FirstValue,
		)
		ch <- prometheus.MustNewConstMetric(
			c.rpcOperationsPerSec,
			prometheus.CounterValue,
			data[rpcOperationsPerSec].FirstValue,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userCount,
			prometheus.GaugeValue,
			data[userCount].FirstValue,
		)
	}

	return nil
}
