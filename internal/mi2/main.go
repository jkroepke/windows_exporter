//go:build windows

package main

import (
	"errors"
	"log"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/windows"
)

var (
	modMi = windows.NewLazySystemDLL("mi.dll")

	procMIApplicationInitialize = modMi.NewProc("MI_Application_InitializeV1")
)

type MI_Result uintptr

const (
	MI_RESULT_OK MI_Result = iota
)

func (r MI_Result) Error() string {
	return r.String()
}

func (r MI_Result) String() string {
	return strconv.FormatUint(uint64(r), 10)
}

type MI_ApplicationPTR struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *MI_ApplicationFTPTR
}

type MI_ApplicationFTPTR struct {
	Close                          uintptr
	NewSession                     uintptr
	NewHostedProvider              uintptr
	NewInstance                    uintptr
	NewDestinationOptions          uintptr
	NewOperationOptions            uintptr
	NewSubscriptionDeliveryOptions uintptr
	NewSerializer                  uintptr
	NewDeserializer                uintptr
	NewInstanceFromClass           uintptr
	NewClass                       uintptr
}

type MI_Application struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *MI_ApplicationFT
}

type MI_ApplicationFT struct {
	Close                          func()
	NewSession                     func(application, protocol, destination, options, callbacks, extendedError, session uintptr) uintptr `call:"std"`
	NewHostedProvider              func()
	NewInstance                    func()
	NewDestinationOptions          func()
	NewOperationOptions            func()
	NewSubscriptionDeliveryOptions func()
	NewSerializer                  func()
	NewDeserializer                func()
	NewInstanceFromClass           func()
	NewClass                       func()
}

// MI_Session represents a session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/ns-mi-mi_session
type MI_Session struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *MI_SessionFT
}

// MI_SessionFT represents the function table for MI_Session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/ns-mi-mi_session
type MI_SessionFT struct {
	Close               uintptr
	GetApplication      uintptr
	GetInstance         uintptr
	ModifyInstance      uintptr
	CreateInstance      uintptr
	DeleteInstance      uintptr
	Invoke              uintptr
	EnumerateInstances  uintptr
	QueryInstances      uintptr
	AssociatorInstances uintptr
	ReferenceInstances  uintptr
	Subscribe           uintptr
	GetClass            uintptr
	EnumerateClasses    uintptr
	TestConnection      uintptr
}

type Protocol string

const (
	ProtocolWINRM   Protocol = "WINRM"
	ProtocolWMIDCOM Protocol = "WMIDCOM"
)

// MI_Application_Initialize initializes the MI application.
// https://docs.microsoft.com/en-us/windows/win32/api/miapi/nf-miapi-mi_application_initializev1
// It is recommended to have only one MI_Application per process.
func MI_Application_Initialize() (*MI_ApplicationPTR, error) {
	flags := uint32(0)

	application := &MI_ApplicationPTR{}

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

	app := &MI_Application{}
	app.reserved1 = application.reserved1
	app.reserved2 = application.reserved2

	var appFn MI_ApplicationFT

	purego.RegisterFunc(&appFn.NewSession, application.ft.NewSession)

	app.ft = &appFn

	return application, nil
}

// MI_Application_NewSession creates a new session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_application_newsession
func MI_Application_NewSession(application *MI_ApplicationPTR, protocol Protocol) (*MI_Session, error) {
	if application.ft == nil {
		return nil, errors.New("MI_Application is not initialized")
	}

	protocolUTF16, err := windows.UTF16PtrFromString(string(protocol))
	if err != nil {
		return nil, err
	}

	session := &MI_Session{}

	r0, _, _ := syscall.SyscallN(
		application.ft.NewSession,
		uintptr(unsafe.Pointer(application)),
		uintptr(unsafe.Pointer(protocolUTF16)),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(session)),
	)

	result := MI_Result(r0)

	if !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return session, nil
}

func main() {
	app, err := MI_Application_Initialize()

	if err != nil && !errors.Is(err, MI_RESULT_OK) {
		log.Fatalf("Failed to initialize MI application: %v", err)
	}

	if app.ft == nil {
		log.Fatal("MI_Application is not initialized")
	}

	session, err := MI_Application_NewSession(app, ProtocolWINRM)

	if err != nil && !errors.Is(err, MI_RESULT_OK) {
		log.Fatalf("Failed to create new session: %v", err)
	}

	if session.ft == nil {
		log.Fatal("MI_Session is not initialized")
	}
}
