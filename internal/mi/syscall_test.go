package mi_test

import (
	"testing"

	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/stretchr/testify/require"
)

func Test_MI_Application_Initialize(t *testing.T) {
	t.Parallel()

	application, err := mi.MI_Application_Initialize()
	require.NoError(t, err)
	require.NotEmpty(t, application)

	session, err := mi.MI_Application_NewSession(application, mi.ProtocolWINRM)
	require.NoError(t, err)
	require.NotEmpty(t, session)
}
