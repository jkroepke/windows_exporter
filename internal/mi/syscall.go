package mi

import (
	"errors"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modMi = windows.NewLazySystemDLL("mi.dll")

	procMIApplicationInitialize = modMi.NewProc("MI_Application_InitializeV1")
)

// Application_Initialize initializes the MI application.
// https://docs.microsoft.com/en-us/windows/win32/api/miapi/nf-miapi-mi_application_initializev1
// It is recommended to have only one Application per process.
// TODO: Uninitialize the application when done.
func Application_Initialize() (*Application, error) {
	flags := uint32(0)

	application := &Application{}

	applicationId, err := windows.UTF16PtrFromString("windows_exporter")
	if err != nil {
		return nil, err
	}

	r0, _, err := procMIApplicationInitialize.Call(
		uintptr(flags), uintptr(unsafe.Pointer(applicationId)), 0, uintptr(unsafe.Pointer(application)),
	)

	if !errors.Is(err, windows.NOERROR) {
		return nil, fmt.Errorf("syscall returned: %w", err)
	}

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return application, nil
}

func MI_Application_Close(application *Application) error {
	r0, _, err := syscall.SyscallN(application.ft.Close, uintptr(unsafe.Pointer(application)))

	if !errors.Is(err, windows.NOERROR) {
		return fmt.Errorf("syscall returned: %w", err)
	}

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return result
	}

	return nil
}

func Operation_Close(operation *Operation) error {
	r0, _, err := syscall.SyscallN(operation.ft.Close, uintptr(unsafe.Pointer(operation)))

	if !errors.Is(err, windows.NOERROR) {
		return fmt.Errorf("syscall returned: %w", err)
	}

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return result
	}

	return nil
}

// Application_NewSession creates a new session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_application_newsession
func Application_NewSession(application *Application, protocol Protocol) (*Session, error) {
	if application.ft == nil {
		return nil, errors.New("application is not initialized")
	}

	session := &Session{}

	callbacks := &SessionCallbacks{
		writeMessage: syscall.NewCallback(func(app *Application, ctx uintptr, channel uint32, msg *uint16) uintptr {
			log.Printf("writeMessage: %s", windows.UTF16PtrToString(msg))

			return 0
		}),
		writeError: syscall.NewCallback(func(app *Application, ctx uintptr, instance uintptr) uintptr {
			log.Printf("writeError: %v\n", instance)

			return 0
		}),
	}

	localhost, err := windows.UTF16PtrFromString("localhost")
	if err != nil {
		return nil, err
	}

	r0, _, _ := syscall.SyscallN(
		application.ft.NewSession,
		uintptr(unsafe.Pointer(application)),
		uintptr(unsafe.Pointer(protocol)),
		uintptr(unsafe.Pointer(localhost)),
		0,
		uintptr(unsafe.Pointer(callbacks)),
		0,
		uintptr(unsafe.Pointer(session)),
	)

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return session, nil
}

// Session_QueryInstances queries instances.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_queryinstances
func Session_QueryInstances(session *Session, flags OperationFlags, namespaceName Namespace, queryDialect QueryDialect, queryExpression string) (*Operation, error) {
	if session.ft == nil {
		return nil, errors.New("MI_Application is not initialized")
	}

	queryExpressionUTF16, err := windows.UTF16PtrFromString(queryExpression)
	if err != nil {
		return nil, err
	}

	operation := &Operation{}

	callbacks := &OperationCallbacks{

		writeMessage: syscall.NewCallback(func(operation *Operation, ctx uintptr, channel uint32, msg *uint16) uintptr {
			log.Printf("writeMessage: %s\n", windows.UTF16PtrToString(msg))

			return 0
		}),
		writeError: syscall.NewCallback(func(operation *Operation, ctx uintptr, instance *Instance) uintptr {
			log.Printf("writeError: %v\n", instance)

			return 0
		}),
	}

	r0, _, _ := syscall.SyscallN(
		session.ft.QueryInstances,
		uintptr(unsafe.Pointer(&flags)),
		0,
		uintptr(unsafe.Pointer(namespaceName)),
		uintptr(unsafe.Pointer(queryDialect)),
		uintptr(unsafe.Pointer(queryExpressionUTF16)),
		uintptr(unsafe.Pointer(callbacks)),
		uintptr(unsafe.Pointer(operation)),
	)

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return operation, nil
}

// Session_TestConnection queries instances.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_testconnection
func Session_TestConnection(session *Session, flags OperationFlags) (*Operation, error) {
	if session.ft == nil {
		return nil, errors.New("session is not initialized")
	}
	operation := &Operation{}

	r0, _, _ := syscall.SyscallN(
		session.ft.TestConnection,
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&flags)),
		0,
		uintptr(unsafe.Pointer(operation)),
	)

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return operation, nil
}

func Operation_GetInstance(operation *Operation) (*Instance, bool, error) {
	if operation.ft == nil {
		return nil, false, errors.New("operation is not initialized")
	}

	var instance *Instance
	var completionDetails *Instance

	var (
		moreResults       uint8
		instanceResult    Result
		errorMessageUTF16 *uint16
	)

	_, _, _ = syscall.SyscallN(
		operation.ft.GetInstance,
		uintptr(unsafe.Pointer(operation)),
		uintptr(unsafe.Pointer(&instance)),
		uintptr(unsafe.Pointer(&moreResults)),
		uintptr(unsafe.Pointer(&instanceResult)),
		uintptr(unsafe.Pointer(&errorMessageUTF16)),
		uintptr(unsafe.Pointer(&completionDetails)),
	)

	// TODO: close instance if not needed
	// if completionDetails.ft != nil {
	// 	mi.Instance_GetElement(instance, "Name")
	// }

	if !errors.Is(instanceResult, MI_RESULT_OK) {
		var detailedError string

		// https://learn.microsoft.com/en-us/previous-versions/cc150671(v=vs.85)
		if completionDetails.ft != nil {
			className, err := Instance_GetClassName(completionDetails)
			count, err := Instance_GetElementCount(completionDetails)
			if count > 0 && err == nil {
				if element, err := Instance_GetElement(completionDetails, "Message"); err == nil {
					detailedError, _ = element.String()
				}
			}

			_ = className
		}

		return nil, false, fmt.Errorf("instance result: %w (%s; %s)", instanceResult, windows.UTF16PtrToString(errorMessageUTF16), detailedError)
	}

	return instance, moreResults != 0, nil
}

func Operation_GetClass(operation *Operation) (*Class, bool, error) {
	if operation.ft == nil {
		return nil, false, errors.New("operation is not initialized")
	}

	var classResult *Class
	var completionDetails *Instance

	var (
		moreResults       uint8
		instanceResult    Result
		errorMessageUTF16 *uint16
	)

	_, _, _ = syscall.SyscallN(
		operation.ft.GetClass,
		uintptr(unsafe.Pointer(operation)),
		uintptr(unsafe.Pointer(&classResult)),
		uintptr(unsafe.Pointer(&moreResults)),
		uintptr(unsafe.Pointer(&instanceResult)),
		uintptr(unsafe.Pointer(&errorMessageUTF16)),
		uintptr(unsafe.Pointer(&completionDetails)),
	)

	// TODO: close instance if not needed
	// if completionDetails.ft != nil {
	// 	mi.Instance_GetElement(instance, "Name")
	// }

	if !errors.Is(instanceResult, MI_RESULT_OK) {
		var detailedError string

		// https://learn.microsoft.com/en-us/previous-versions/cc150671(v=vs.85)
		if completionDetails.ft != nil {
			className, err := Instance_GetClassName(completionDetails)
			count, err := Instance_GetElementCount(completionDetails)
			if count > 0 && err == nil {
				if element, err := Instance_GetElement(completionDetails, "Message"); err == nil {
					detailedError, _ = element.String()
				}
			}

			_ = className
		}

		return nil, false, fmt.Errorf("instance result: %w (%s; %s)", instanceResult, windows.UTF16PtrToString(errorMessageUTF16), detailedError)
	}

	return classResult, moreResults != 0, nil
}

func Instance_GetElement(instance *Instance, elementName string) (*Element, error) {
	if instance.ft == nil {
		return nil, errors.New("instance is not initialized")
	}

	elementNameUTF16, err := windows.UTF16PtrFromString(elementName)
	if err != nil {
		return nil, err
	}

	value := &Value{}
	var (
		valueType  ValueType
		valueFlags uint32
		valueIndex uint32
	)

	r0, _, _ := syscall.SyscallN(
		instance.ft.GetElement,
		uintptr(unsafe.Pointer(instance)),
		uintptr(unsafe.Pointer(elementNameUTF16)),
		uintptr(unsafe.Pointer(value)),
		uintptr(unsafe.Pointer(&valueType)),
		uintptr(unsafe.Pointer(&valueFlags)),
		uintptr(unsafe.Pointer(&valueIndex)),
	)

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return nil, result
	}

	return &Element{
		value:     nil,
		flags:     valueFlags,
		valueType: valueType,
	}, nil
}

func Instance_GetElementCount(instance *Instance) (uint32, error) {
	if instance.ft == nil {
		return 0, errors.New("instance is not initialized")
	}

	var count uint32

	r0, _, _ := syscall.SyscallN(
		instance.ft.GetElementCount,
		uintptr(unsafe.Pointer(instance)),
		uintptr(unsafe.Pointer(&count)),
	)

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return 0, result
	}

	return count, nil
}

func Instance_GetClassName(instance *Instance) (string, error) {
	if instance.ft == nil {
		return "", errors.New("instance is not initialized")
	}

	var classNameUTF16 *uint16

	r0, _, _ := syscall.SyscallN(
		instance.ft.GetElementCount,
		uintptr(unsafe.Pointer(instance)),
		uintptr(unsafe.Pointer(&classNameUTF16)),
	)

	if result := Result(r0); !errors.Is(result, MI_RESULT_OK) {
		return "", result
	}

	return windows.UTF16PtrToString(classNameUTF16), nil
}
