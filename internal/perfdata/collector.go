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

package perfdata

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/windows"
)

//nolint:gochecknoglobals
var (
	InstancesAll   = []string{"*"}
	InstancesTotal = []string{InstanceTotal}
)

type CounterValues = map[string]map[string]CounterValue

type Collector[T any] struct {
	object                string
	counters              map[string]Counter
	handle                pdhQueryHandle
	totalCounterRequested bool
	mu                    sync.RWMutex

	NameFieldIndex   []int
	requestCollectCh chan []T
	resultCollectCh  chan error
}

type Counter struct {
	Name       string
	FieldIndex []int
	Desc       string
	Instances  map[string]pdhCounterHandle
	Type       uint32
	Frequency  int64
}

func NewCollector[T any](object string, instances []string) (*Collector[T], error) {
	var handle pdhQueryHandle

	if ret := PdhOpenQuery(0, 0, &handle); ret != ErrorSuccess {
		return nil, NewPdhError(ret)
	}

	if len(instances) == 0 {
		instances = []string{InstanceEmpty}
	}

	var zero [0]T
	tt := reflect.TypeOf(zero).Elem()
	if tt.Kind() != reflect.Struct {
		return nil, errors.New("T must be a struct")
	}

	collector := &Collector[T]{
		object:                object,
		counters:              make(map[string]Counter, tt.NumField()),
		handle:                handle,
		totalCounterRequested: slices.Contains(instances, InstanceTotal),
		mu:                    sync.RWMutex{},
	}

	errs := make([]error, 0, tt.NumField())

	for _, field := range reflect.VisibleFields(tt) {
		counterName, ok := field.Tag.Lookup("pdh")
		if !ok {
			continue
		}

		if field.Name == "Name" {
			collector.NameFieldIndex = field.Index
		}

		if counterName == "*" {
			return nil, errors.New("wildcard counters are not supported")
		}

		counter := Counter{
			Name:       counterName,
			FieldIndex: field.Index,
			Instances:  make(map[string]pdhCounterHandle, len(instances)),
		}

		var counterPath string

		for _, instance := range instances {
			counterPath = formatCounterPath(object, instance, counterName)

			var counterHandle pdhCounterHandle

			if ret := PdhAddEnglishCounter(handle, counterPath, 0, &counterHandle); ret != ErrorSuccess {
				errs = append(errs, fmt.Errorf("failed to add counter %s: %w", counterPath, NewPdhError(ret)))

				continue
			}

			counter.Instances[instance] = counterHandle

			if counter.Type != 0 {
				continue
			}

			// Get the info with the current buffer size
			bufLen := uint32(0)

			if ret := PdhGetCounterInfo(counterHandle, 0, &bufLen, nil); ret != PdhMoreData {
				errs = append(errs, fmt.Errorf("PdhGetCounterInfo: %w", NewPdhError(ret)))

				continue
			}

			buf := make([]byte, bufLen)
			if ret := PdhGetCounterInfo(counterHandle, 0, &bufLen, &buf[0]); ret != ErrorSuccess {
				errs = append(errs, fmt.Errorf("PdhGetCounterInfo: %w", NewPdhError(ret)))

				continue
			}

			ci := (*PdhCounterInfo)(unsafe.Pointer(&buf[0]))
			counter.Type = ci.DwType
			counter.Desc = windows.UTF16PtrToString(ci.SzExplainText)

			if counter.Type == PERF_ELAPSED_TIME {
				if ret := PdhGetCounterTimeBase(counterHandle, &counter.Frequency); ret != ErrorSuccess {
					errs = append(errs, fmt.Errorf("PdhGetCounterTimeBase: %w", NewPdhError(ret)))

					continue
				}
			}
		}

		collector.counters[counterName] = counter
	}

	if err := errors.Join(errs...); err != nil {
		return collector, fmt.Errorf("failed to initialize collector: %w", err)
	}

	if len(collector.counters) == 0 {
		return nil, errors.New("no counters configured")
	}

	collector.requestCollectCh = make(chan []T)
	collector.resultCollectCh = make(chan error)

	go collector.collectRoutine()

	counterValues := make([]T, 0)

	if err := collector.Collect(counterValues); err != nil && !errors.Is(err, ErrNoData) {
		return collector, fmt.Errorf("failed to collect initial data: %w", err)
	}

	return collector, nil
}

func (c *Collector[T]) Describe() map[string]string {
	if c == nil {
		return map[string]string{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	desc := make(map[string]string, len(c.counters))

	for _, counter := range c.counters {
		desc[counter.Name] = counter.Desc
	}

	return desc
}

func (c *Collector[T]) Collect(values []T) error {
	if c == nil {
		return ErrPerformanceCounterNotInitialized
	}

	if values == nil {
		values = make([]T, 0)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.counters) == 0 || c.handle == 0 || c.requestCollectCh == nil || c.resultCollectCh == nil {
		return ErrPerformanceCounterNotInitialized
	}

	c.requestCollectCh <- values

	return <-c.resultCollectCh
}

func (c *Collector[T]) collectRoutine() {
	buf := make([]byte, 0)

	// Get the info with the current buffer size
	var (
		bytesNeeded uint32
		itemCount   uint32
	)

	for values := range c.requestCollectCh {
		if ret := PdhCollectQueryData(c.handle); ret != ErrorSuccess {
			c.resultCollectCh <- fmt.Errorf("failed to collect query data: %w", NewPdhError(ret))

			continue
		}

		err := (func() error {
			// Clear the values slice
			clear(values)
			values = values[:0]

			for _, counter := range c.counters {
				for _, instance := range counter.Instances {
					// Get the info with the current buffer size
					bytesNeeded = uint32(cap(buf))
					itemCount = 0

					for {
						ret := PdhGetRawCounterArray(instance, &bytesNeeded, &itemCount, &buf[0])

						if ret == ErrorSuccess {
							break
						}

						if err := NewPdhError(ret); ret != PdhMoreData && !isKnownCounterDataError(err) {
							return fmt.Errorf("PdhGetRawCounterArray: %w", err)
						}

						if bytesNeeded <= uint32(cap(buf)) {
							return fmt.Errorf("PdhGetRawCounterArray reports buffer too small (%d), but buffer is large enough (%d): %w", uint32(cap(buf)), bytesNeeded, NewPdhError(ret))
						}

						buf = make([]byte, bytesNeeded)
					}

					items := unsafe.Slice((*PdhRawCounterItem)(unsafe.Pointer(&buf[0])), itemCount)

					var metricType prometheus.ValueType
					if val, ok := supportedCounterTypes[counter.Type]; ok {
						metricType = val
					} else {
						metricType = prometheus.GaugeValue
					}

					if len(values) == 0 {
						values = make([]T, len(items))
					}

					for instanceIndex, item := range items {
						if item.RawValue.CStatus == PdhCstatusValidData || item.RawValue.CStatus == PdhCstatusNewData {
							instanceName := windows.UTF16PtrToString(item.SzName)
							if strings.HasSuffix(instanceName, InstanceTotal) && !c.totalCounterRequested {
								continue
							}

							if instanceName == "" || instanceName == "*" {
								instanceName = InstanceEmpty
							}

							counterValue := CounterValue{
								Type: metricType,
							}

							// This is a workaround for the issue with the elapsed time counter type.
							// Source: https://github.com/prometheus-community/windows_exporter/pull/335/files#diff-d5d2528f559ba2648c2866aec34b1eaa5c094dedb52bd0ff22aa5eb83226bd8dR76-R83
							// Ref: https://learn.microsoft.com/en-us/windows/win32/perfctrs/calculating-counter-values

							switch counter.Type {
							case PERF_ELAPSED_TIME:
								counterValue.FirstValue = float64((item.RawValue.FirstValue - WindowsEpoch) / counter.Frequency)
							case PERF_100NSEC_TIMER, PERF_PRECISION_100NS_TIMER:
								counterValue.FirstValue = float64(item.RawValue.FirstValue) * TicksToSecondScaleFactor
							case PERF_AVERAGE_BULK, PERF_RAW_FRACTION:
								counterValue.FirstValue = float64(item.RawValue.FirstValue)
								counterValue.SecondValue = float64(item.RawValue.SecondValue)
							default:
								counterValue.FirstValue = float64(item.RawValue.FirstValue)
							}

							value := reflect.ValueOf(values[instanceIndex]).Elem()

							field, err := value.FieldByIndexErr(counter.FieldIndex)
							if err != nil {
								return fmt.Errorf("failed to get field by index: %w", err)
							}

							field.Set(reflect.ValueOf(counterValue))

							nameField, err := value.FieldByIndexErr(c.NameFieldIndex)
							if err != nil {
								return fmt.Errorf("failed to get name field by index: %w", err)
							}

							nameField.SetString(instanceName)
						}
					}
				}
			}

			return nil
		})()

		if err == nil && len(values) == 0 {
			err = ErrNoData
		}

		c.resultCollectCh <- err
	}
}

func (c *Collector) Close() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	PdhCloseQuery(c.handle)

	c.handle = 0

	close(c.requestCollectCh)
	close(c.resultCollectCh)
	close(c.errorCh)

	c.resultCollectCh = nil
	c.requestCollectCh = nil
	c.errorCh = nil
}

func formatCounterPath(object, instance, counterName string) string {
	var counterPath string

	if instance == InstanceEmpty {
		counterPath = fmt.Sprintf(`\%s\%s`, object, counterName)
	} else {
		counterPath = fmt.Sprintf(`\%s(%s)\%s`, object, instance, counterName)
	}

	return counterPath
}

func isKnownCounterDataError(err error) bool {
	var pdhErr *Error

	return errors.As(err, &pdhErr) && (pdhErr.ErrorCode == PdhInvalidData ||
		pdhErr.ErrorCode == PdhCalcNegativeDenominator ||
		pdhErr.ErrorCode == PdhCalcNegativeValue ||
		pdhErr.ErrorCode == PdhCstatusInvalidData ||
		pdhErr.ErrorCode == PdhCstatusNoInstance ||
		pdhErr.ErrorCode == PdhNoData)
}
