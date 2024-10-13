package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modMi = windows.NewLazySystemDLL("mi.dll")

	procMIApplicationInitialize = modMi.NewProc("MI_Application_InitializeV1")
)

type MI_Application struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *MI_ApplicationFT
}

type MI_ApplicationFT struct {
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

// MI_Application_Initialize initializes the MI application.
// https://docs.microsoft.com/en-us/windows/win32/api/miapi/nf-miapi-mi_application_initializev1
// It is recommended to have only one MI_Application per process.
func MI_Application_Initialize() (*MI_Application, uint64) {
	flags := uint32(0)

	application := &MI_Application{}

	r0, _, _ := procMIApplicationInitialize.Call(
		uintptr(flags), 0, 0, uintptr(unsafe.Pointer(application)),
	)

	return application, uint64(r0)
}

func main() {
	app, statusCode := MI_Application_Initialize()

	if statusCode != 0 {
		panic("Failed to initialize MI application")
	}

	if app.ft == nil {
		panic("MI_Application is not initialized")
	}
}
