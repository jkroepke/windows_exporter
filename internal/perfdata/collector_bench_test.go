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

package perfdata_test

import (
	"testing"

	"github.com/prometheus-community/windows_exporter/internal/perfdata"
	"github.com/stretchr/testify/require"
)

type Process struct {
	Name                    string
	ProcessorTime           perfdata.CounterValue `pdh:"% Processor Time"`
	PrivilegedTime          perfdata.CounterValue `pdh:"% Privileged Time"`
	UserTime                perfdata.CounterValue `pdh:"% User Time"`
	CreatingProcessID       perfdata.CounterValue `pdh:"Creating Process ID"`
	ElapsedTime             perfdata.CounterValue `pdh:"Elapsed Time"`
	HandleCount             perfdata.CounterValue `pdh:"Handle Count"`
	IDProcess               perfdata.CounterValue `pdh:"ID Process"`
	IODataBytesPerSec       perfdata.CounterValue `pdh:"IO Data Bytes/sec"`
	IODataOperationsPerSec  perfdata.CounterValue `pdh:"IO Data Operations/sec"`
	IOOtherBytesPerSec      perfdata.CounterValue `pdh:"IO Other Bytes/sec"`
	IOOtherOperationsPerSec perfdata.CounterValue `pdh:"IO Other Operations/sec"`
	IOReadBytesPerSec       perfdata.CounterValue `pdh:"IO Read Bytes/sec"`
	IOReadOperationsPerSec  perfdata.CounterValue `pdh:"IO Read Operations/sec"`
	IOWriteBytesPerSec      perfdata.CounterValue `pdh:"IO Write Bytes/sec"`
	IOWriteOperationsPerSec perfdata.CounterValue `pdh:"IO Write Operations/sec"`
	PageFaultsPerSec        perfdata.CounterValue `pdh:"Page Faults/sec"`
	PageFileBytesPeak       perfdata.CounterValue `pdh:"Page File Bytes Peak"`
	PageFileBytes           perfdata.CounterValue `pdh:"Page File Bytes"`
	PoolNonpagedBytes       perfdata.CounterValue `pdh:"Pool Nonpaged Bytes"`
	PoolPagedBytes          perfdata.CounterValue `pdh:"Pool Paged Bytes"`
	PriorityBase            perfdata.CounterValue `pdh:"Priority Base"`
	PrivateBytes            perfdata.CounterValue `pdh:"Private Bytes"`
	ThreadCount             perfdata.CounterValue `pdh:"Thread Count"`
	VirtualBytesPeak        perfdata.CounterValue `pdh:"Virtual Bytes Peak"`
	VirtualBytes            perfdata.CounterValue `pdh:"Virtual Bytes"`
	WorkingSetPrivate       perfdata.CounterValue `pdh:"Working Set - Private"`
	WorkingSetPeak          perfdata.CounterValue `pdh:"Working Set Peak"`
	WorkingSet              perfdata.CounterValue `pdh:"Working Set"`
}

func BenchmarkTestCollector(b *testing.B) {
	performanceData, err := perfdata.NewCollector[Process]("Process", []string{"*"})
	require.NoError(b, err)

	processes := make([]Process, 0)

	for i := 0; i < b.N; i++ {
		_ = performanceData.Collect(&processes)
	}

	performanceData.Close()

	b.ReportAllocs()
}
