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

package pdh

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

	nameIndexValue int

	collectCh chan []T
	errorCh   chan error
}

type Counter struct {
	Name       string
	Desc       string
	MetricType prometheus.ValueType
	Instances  map[string]pdhCounterHandle
	Type       uint32
	Frequency  int64

	FieldIndexValue       int
	FieldIndexSecondValue int
}

func NewCollector[T any](object string, instances []string) (*Collector[T], error) {
	var handle pdhQueryHandle

	if ret := PdhOpenQuery(0, 0, &handle); ret != ErrorSuccess {
		return nil, NewPdhError(ret)
	}

	if len(instances) == 0 {
		instances = []string{InstanceEmpty}
	}

	var values *T

	t := reflect.TypeOf(values).Elem()

	collector := &Collector[T]{
		object:                object,
		counters:              make(map[string]Counter, t.NumField()),
		handle:                handle,
		totalCounterRequested: slices.Contains(instances, InstanceTotal),
		mu:                    sync.RWMutex{},
	}

	errs := make([]error, 0, t.NumField())

	if f, ok := t.FieldByName("Name"); ok {
		if f.Type.Kind() == reflect.String {
			collector.nameIndexValue = f.Index[0]
		}
	}

	for _, f := range reflect.VisibleFields(t) {
		counterName, ok := f.Tag.Lookup("pdh")
		if !ok {
			continue
		}

		if f.Type.Kind() != reflect.Float64 {
			errs = append(errs, fmt.Errorf("field %s must be a float64", f.Name))
			continue
		}

		counter := Counter{
			Name:      counterName,
			Instances: make(map[string]pdhCounterHandle, len(instances)),
		}

		if _, ok = f.Tag.Lookup("secondvalue"); ok {
			counter := collector.counters[counterName]
			counter.FieldIndexSecondValue = f.Index[0]
			collector.counters[counterName] = counter
			continue
		} else {
			counter.FieldIndexValue = f.Index[0]
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
			counter.Desc = windows.UTF16PtrToString(ci.SzExplainText)

			if val, ok := SupportedCounterTypes[counter.Type]; ok {
				counter.MetricType = val
			} else {
				counter.MetricType = prometheus.GaugeValue
			}

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

	collector.collectCh = make(chan []T)
	collector.errorCh = make(chan error)

	go collector.collectRoutine()

	var collectValues []T

	if err := collector.Collect(collectValues); err != nil && !errors.Is(err, ErrNoData) {
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

func (c *Collector[T]) Collect(v []T) error {
	if c == nil {
		return ErrPerformanceCounterNotInitialized
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.counters) == 0 || c.handle == 0 || c.collectCh == nil || c.errorCh == nil {
		return ErrPerformanceCounterNotInitialized
	}

	c.collectCh <- v

	return <-c.errorCh
}

func (c *Collector[T]) collectRoutine() {
	var (
		err         error
		itemCount   uint32
		items       []PdhRawCounterItem
		bytesNeeded uint32
	)

	buf := make([]byte, 1)

	for data := range c.collectCh {
		if ret := PdhCollectQueryData(c.handle); ret != ErrorSuccess {
			c.errorCh <- fmt.Errorf("failed to collect query data: %w", NewPdhError(ret))

			continue
		}

		clear(data)
		data = data[:0]

		indexMap := map[string]int{}

		err = (func() error {
			for _, counter := range c.counters {
				for _, instance := range counter.Instances {
					// Get the info with the current buffer size
					bytesNeeded = uint32(cap(buf))

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

					items = unsafe.Slice((*PdhRawCounterItem)(unsafe.Pointer(&buf[0])), itemCount)

					if len(data) < int(itemCount) {
						slices.Grow(data, int(itemCount))
					}

					for _, item := range items {
						if item.RawValue.CStatus == PdhCstatusValidData || item.RawValue.CStatus == PdhCstatusNewData {
							instanceName := windows.UTF16PtrToString(item.SzName)
							if strings.HasSuffix(instanceName, InstanceTotal) && !c.totalCounterRequested {
								continue
							}

							if instanceName == "" || instanceName == "*" {
								instanceName = InstanceEmpty
							}

							var (
								index int
								ok    bool
							)

							if index, ok = indexMap[instanceName]; !ok {
								var counterValues T

								index = len(data)
								indexMap[instanceName] = index
								data[index] = counterValues

								s := reflect.ValueOf(&data[index]).Elem()
								s.Field(c.nameIndexValue).SetString(instanceName)
							}

							s := reflect.ValueOf(&data[index]).Elem()
							if counter.FieldIndexValue == 0 {
								continue
							}

							// This is a workaround for the issue with the elapsed time counter type.
							// Source: https://github.com/prometheus-community/windows_exporter/pull/335/files#diff-d5d2528f559ba2648c2866aec34b1eaa5c094dedb52bd0ff22aa5eb83226bd8dR76-R83
							// Ref: https://learn.microsoft.com/en-us/windows/win32/perfctrs/calculating-counter-values
							switch counter.Type {
							case PERF_ELAPSED_TIME:
								s.Field(counter.FieldIndexValue).SetFloat(float64((item.RawValue.FirstValue - WindowsEpoch) / counter.Frequency))
							case PERF_100NSEC_TIMER, PERF_PRECISION_100NS_TIMER:
								s.Field(counter.FieldIndexValue).SetFloat(float64(item.RawValue.FirstValue) * TicksToSecondScaleFactor)
							case PERF_AVERAGE_BULK, PERF_RAW_FRACTION:
								if counter.FieldIndexSecondValue != 0 {
									s.Field(counter.FieldIndexSecondValue).SetFloat(float64(item.RawValue.SecondValue))
								}
								fallthrough
							default:
								s.Field(counter.FieldIndexValue).SetFloat(float64(item.RawValue.FirstValue))
							}
						}
					}
				}
			}

			return nil
		})()

		if err == nil && len(data) == 0 {
			err = ErrNoData
		}

		c.errorCh <- err
	}
}

func (c *Collector[T]) Close() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	PdhCloseQuery(c.handle)

	c.handle = 0

	if c.collectCh != nil {
		close(c.collectCh)
	}

	if c.errorCh != nil {
		close(c.errorCh)
	}

	c.collectCh = nil
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
