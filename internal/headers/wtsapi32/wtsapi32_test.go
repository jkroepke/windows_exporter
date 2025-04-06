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

package wtsapi32_test

import (
	"log/slog"
	"testing"

	"github.com/prometheus-community/windows_exporter/internal/headers/wtsapi32"
	"github.com/stretchr/testify/require"
)

func TestWTSEnumerateSessionsEx(t *testing.T) {
	wts, err := wtsapi32.WTSOpenServer("")
	require.NoError(t, err)

	logger := slog.New(slog.DiscardHandler)

	sessions, err := wtsapi32.WTSEnumerateSessionsEx(wts, logger)
	require.NoError(t, err)
	require.NotEmpty(t, sessions)

	err = wtsapi32.WTSCloseServer(wts)
	require.NoError(t, err)
}
