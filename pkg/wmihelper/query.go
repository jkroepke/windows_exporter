package wmihelper

import (
	"fmt"

	"github.com/go-kit/log"
	cim "github.com/microsoft/wmi/pkg/wmiinstance"
)

func QueryAll[S []E, E any](logger log.Logger, wmiSession *cim.WmiSession, className string, dst *S) error {
	return RawQueryAll(logger, wmiSession, "SELECT * FROM "+className, dst)
}

func RawQueryAll[S []E, E any](logger log.Logger, wmiSession *cim.WmiSession, query string, dst *S) error {
	wmiInstances, err := wmiSession.QueryInstances(query)
	if err != nil {
		return fmt.Errorf("failed to query instances: %w", err)
	}

	defer CloseInstances(logger, wmiInstances)

	if err = CastInstances(wmiInstances, dst); err != nil {
		return fmt.Errorf("failed to cast WMI instance to struct: %w", err)
	}

	return nil
}
