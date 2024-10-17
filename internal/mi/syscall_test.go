package mi_test

import (
	"testing"

	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/stretchr/testify/require"
)

func Test_MI_Application_Initialize(t *testing.T) {
	application, err := mi.Application_Initialize()
	require.NoError(t, err)
	require.NotEmpty(t, application)

	err = mi.MI_Application_Close(application)
	require.NoError(t, err)
}

func Test_MI_Query(t *testing.T) {
	t.Parallel()

	application, err := mi.Application_Initialize()
	require.NoError(t, err)
	require.NotEmpty(t, application)

	session, err := mi.Application_NewSession(application, mi.ProtocolWINRM)
	require.NoError(t, err)
	require.NotEmpty(t, session)
	/*
		operation, err := mi.Session_TestConnection(session, mi.OperationNoFlags)

		require.NoError(t, err)
		require.NotEmpty(t, operation)

		for {
			class, moreResults, err := mi.Operation_GetInstance(operation)
			require.NoError(t, err)
			require.NotEmpty(t, class)

			if !moreResults {
				break
			}
		}

		require.NoError(t, mi.Operation_Close(operation))

	*/
	operation, err := mi.Session_QueryInstances(session, mi.OperationFlagsNoRTTI, mi.NamespaceRootCIMv2, mi.QueryDialectWQL,
		"SELECT Architecture, DeviceId, Description, Family, L2CacheSize, L3CacheSize, Name, ThreadCount, NumberOfCores, NumberOfEnabledCore, NumberOfLogicalProcessors FROM Win32_Processor")

	require.NoError(t, err)
	require.NotEmpty(t, operation)
	for {
		instance, moreResults, err := mi.Operation_GetInstance(operation)
		require.NoError(t, err)
		require.NotEmpty(t, instance)

		if !moreResults {
			break
		}
	}
}
