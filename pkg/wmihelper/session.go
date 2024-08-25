package wmihelper

import (
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	cim "github.com/microsoft/wmi/pkg/wmiinstance"
)

func OpenSession(sessionManager *cim.WmiSessionManager, namespace string) (*cim.WmiSession, error) {
	wmiSession, err := sessionManager.GetLocalSession(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to WMI: %w", err)
	}

	connected, err := wmiSession.Connect()
	if !connected || err != nil {
		return nil, fmt.Errorf("failed to connect to WMI: %w", err)
	}

	return wmiSession, nil
}

func CloseInstances(logger log.Logger, instances []*cim.WmiInstance) {
	for _, instance := range instances {
		if err := instance.Close(); err != nil {
			_ = level.Warn(logger).Log("msg", "failed to close WMI instance", "err", err)
		}
	}
}
