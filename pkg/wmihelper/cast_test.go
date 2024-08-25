package wmihelper_test

import (
	"testing"

	cim "github.com/microsoft/wmi/pkg/wmiinstance"
	"github.com/prometheus-community/windows_exporter/pkg/wmihelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Win32Processor struct {
	Architecture uint32
	DeviceID     string
	Description  string
	Family       uint16
	L2CacheSize  uint32
	L3CacheSize  uint32
	Name         string
}

func TestCastToStruct(t *testing.T) {
	wmiSessionManager := cim.NewWmiSessionManager()
	defer wmiSessionManager.Dispose()

	wmiSession, err := wmiSessionManager.GetLocalSession("root\\cimv2")
	require.NoError(t, err)

	connect, err := wmiSession.Connect()
	require.NoError(t, err)
	require.True(t, connect)

	defer wmiSession.Dispose()

	instances, err := wmiSession.EnumerateInstances("Win32_Processor")
	require.NoError(t, err)

	var processors []Win32Processor
	err = wmihelper.CastInstances(instances, &processors)
	require.NoError(t, err)

	require.NotEmpty(t, processors)
	assert.Equal(t, len(instances), len(processors))
	assert.NotEmpty(t, processors[0].Architecture)
	assert.Equal(t, "CPU0", processors[0].DeviceID)
	assert.NotEmpty(t, processors[0].Description)
	assert.NotEmpty(t, processors[0].Family)
	assert.NotEmpty(t, processors[0].L2CacheSize)
	assert.NotEmpty(t, processors[0].Name)
}
