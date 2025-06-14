// SPDX-License-Identifier: Apache-2.0
//
// Copyright The Prometheus Authors
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

package mi_test

import (
	"log"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetProcessHandleCount = modkernel32.NewProc("GetProcessHandleCount")
)

func GetProcessHandleCount(handle windows.Handle) uint32 {
	var count uint32
	r1, _, err := procGetProcessHandleCount.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&count)),
	)
	if r1 != 1 {
		panic(err)
	} else {
		return count
	}
}

func Test_MI_FD(t *testing.T) {
	log.Printf("1 Process handle count: %d", GetProcessHandleCount(windows.CurrentProcess()))

	application, err := mi.ApplicationInitialize()
	require.NoError(t, err)
	require.NotEmpty(t, application)

	destinationOptions, err := application.NewDestinationOptions()
	require.NoError(t, err)
	require.NotEmpty(t, destinationOptions)

	err = destinationOptions.SetTimeout(1 * time.Second)
	require.NoError(t, err)

	err = destinationOptions.SetLocale(mi.LocaleEnglish)
	require.NoError(t, err)

	session, err := application.NewSession(destinationOptions)
	require.NoError(t, err)
	require.NotEmpty(t, session)

	for range 100 {
		log.Printf("2 Process handle count: %d", GetProcessHandleCount(windows.CurrentProcess()))

		operation, err := session.QueryInstances(mi.OperationFlagsStandardRTTI, nil, mi.NamespaceRootCIMv2, mi.QueryDialectWQL, "select Name from win32_process where handle = 0")

		require.NoError(t, err)
		require.NotEmpty(t, operation)

		instance, moreResults, err := operation.GetInstance()
		require.NoError(t, err)
		require.NotEmpty(t, instance)

		count, err := instance.GetElementCount()
		require.NoError(t, err)
		require.NotZero(t, count)

		element, err := instance.GetElement("Name")
		require.NoError(t, err)
		require.NotEmpty(t, element)

		value, err := element.GetValue()
		require.NoError(t, err)
		require.Equal(t, "System Idle Process", value)
		require.NotEmpty(t, value)

		require.False(t, moreResults)

		err = operation.Close()
		require.NoError(t, err)
	}

	log.Printf("3 Process handle count: %d", GetProcessHandleCount(windows.CurrentProcess()))

	err = session.Close()
	require.NoError(t, err)

	err = application.Close()
	require.NoError(t, err)

	log.Printf("4 Process handle count: %d", GetProcessHandleCount(windows.CurrentProcess()))
}
