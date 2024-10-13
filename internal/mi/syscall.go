package mi

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modMi = windows.NewLazySystemDLL("mi.dll")

	procMIApplicationInitialize = modMi.NewProc("MI_Application_InitializeV1")
)

// MI_Application_Initialize initializes the MI application.
// https://docs.microsoft.com/en-us/windows/win32/api/miapi/nf-miapi-mi_application_initializev1
// It is recommended to have only one MI_Application per process.
func MI_Application_Initialize() (*MI_Application, error) {
	flags := uint32(0)

	application := &MI_Application{}

	applicationId, err := windows.UTF16PtrFromString("windows_exporter")
	if err != nil {
		return nil, err
	}

	r0, _, _ := procMIApplicationInitialize.Call(
		uintptr(flags), uintptr(unsafe.Pointer(applicationId)), 0, uintptr(unsafe.Pointer(application)),
	)

	result := MI_Result(r0)

	if !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return application, nil
}

// MI_Application_NewSession creates a new session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_application_newsession
func MI_Application_NewSession(application *MI_Application, protocol Protocol) (*MI_Session, error) {
	if application.ft == nil {
		return nil, errors.New("MI_Application is not initialized")
	}

	protocolUTF16, err := windows.UTF16PtrFromString(string(protocol))
	if err != nil {
		return nil, err
	}

	session := &MI_Session{}

	r0 := application.ft.NewSession(
		uintptr(unsafe.Pointer(application)),
		uintptr(unsafe.Pointer(protocolUTF16)),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(session)),
	)

	result := r0

	if !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return session, nil
}
