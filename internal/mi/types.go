package mi

var _ error = (*MI_Result)(nil)

type Protocol string

const (
	ProtocolWINRM   Protocol = "WINRM"
	ProtocolWMIDCOM Protocol = "WMIDCOM"
)

type MI_Result uintptr

const (
	MI_RESULT_OK MI_Result = iota
	MI_RESULT_FAILED
	MI_RESULT_ACCESS_DENIED
	MI_RESULT_INVALID_NAMESPACE
	MI_RESULT_INVALID_PARAMETER
	MI_RESULT_INVALID_CLASS
	MI_RESULT_NOT_FOUND
	MI_RESULT_NOT_SUPPORTED
	MI_RESULT_CLASS_HAS_CHILDREN
	MI_RESULT_CLASS_HAS_INSTANCES
	MI_RESULT_INVALID_SUPERCLASS
	MI_RESULT_ALREADY_EXISTS
	MI_RESULT_NO_SUCH_PROPERTY
	MI_RESULT_TYPE_MISMATCH
	MI_RESULT_QUERY_LANGUAGE_NOT_SUPPORTED
	MI_RESULT_INVALID_QUERY
	MI_RESULT_METHOD_NOT_AVAILABLE
	MI_RESULT_METHOD_NOT_FOUND
	MI_RESULT_NAMESPACE_NOT_EMPTY
	MI_RESULT_INVALID_ENUMERATION_CONTEXT
	MI_RESULT_INVALID_OPERATION_TIMEOUT
	MI_RESULT_PULL_HAS_BEEN_ABANDONED
	MI_RESULT_PULL_CANNOT_BE_ABANDONED
	MI_RESULT_FILTERED_ENUMERATION_NOT_SUPPORTED
	MI_RESULT_CONTINUATION_ON_ERROR_NOT_SUPPORTED
	MI_RESULT_SERVER_LIMITS_EXCEEDED
	MI_RESULT_SERVER_IS_SHUTTING_DOWN
)

func (r MI_Result) Error() string {
	return r.String()
}

func (r MI_Result) String() string {
	switch r {
	case MI_RESULT_OK:
		return "MI_RESULT_OK"
	case MI_RESULT_FAILED:
		return "MI_RESULT_FAILED"
	case MI_RESULT_ACCESS_DENIED:
		return "MI_RESULT_ACCESS_DENIED"
	case MI_RESULT_INVALID_NAMESPACE:
		return "MI_RESULT_INVALID_NAMESPACE"
	case MI_RESULT_INVALID_PARAMETER:
		return "MI_RESULT_INVALID_PARAMETER"
	case MI_RESULT_INVALID_CLASS:
		return "MI_RESULT_INVALID_CLASS"
	case MI_RESULT_NOT_FOUND:
		return "MI_RESULT_NOT_FOUND"
	case MI_RESULT_NOT_SUPPORTED:
		return "MI_RESULT_NOT_SUPPORTED"
	case MI_RESULT_CLASS_HAS_CHILDREN:
		return "MI_RESULT_CLASS_HAS_CHILDREN"
	case MI_RESULT_CLASS_HAS_INSTANCES:
		return "MI_RESULT_CLASS_HAS_INSTANCES"
	case MI_RESULT_INVALID_SUPERCLASS:
		return "MI_RESULT_INVALID_SUPERCLASS"
	case MI_RESULT_ALREADY_EXISTS:
		return "MI_RESULT_ALREADY_EXISTS"
	case MI_RESULT_NO_SUCH_PROPERTY:
		return "MI_RESULT_NO_SUCH_PROPERTY"
	case MI_RESULT_TYPE_MISMATCH:
		return "MI_RESULT_TYPE_MISMATCH"
	case MI_RESULT_QUERY_LANGUAGE_NOT_SUPPORTED:
		return "MI_RESULT_QUERY_LANGUAGE_NOT_SUPPORTED"
	case MI_RESULT_INVALID_QUERY:
		return "MI_RESULT_INVALID_QUERY"
	case MI_RESULT_METHOD_NOT_AVAILABLE:
		return "MI_RESULT_METHOD_NOT_AVAILABLE"
	case MI_RESULT_METHOD_NOT_FOUND:
		return "MI_RESULT_METHOD_NOT_FOUND"
	case MI_RESULT_NAMESPACE_NOT_EMPTY:
		return "MI_RESULT_NAMESPACE_NOT_EMPTY"
	case MI_RESULT_INVALID_ENUMERATION_CONTEXT:
		return "MI_RESULT_INVALID_ENUMERATION_CONTEXT"
	case MI_RESULT_INVALID_OPERATION_TIMEOUT:
		return "MI_RESULT_INVALID_OPERATION_TIMEOUT"
	case MI_RESULT_PULL_HAS_BEEN_ABANDONED:
		return "MI_RESULT_PULL_HAS_BEEN_ABANDONED"
	case MI_RESULT_PULL_CANNOT_BE_ABANDONED:
		return "MI_RESULT_PULL_CANNOT_BE_ABANDONED"
	case MI_RESULT_FILTERED_ENUMERATION_NOT_SUPPORTED:
		return "MI_RESULT_FILTERED_ENUMERATION_NOT_SUPPORTED"
	case MI_RESULT_CONTINUATION_ON_ERROR_NOT_SUPPORTED:
		return "MI_RESULT_CONTINUATION_ON_ERROR_NOT_SUPPORTED"
	case MI_RESULT_SERVER_LIMITS_EXCEEDED:
		return "MI_RESULT_SERVER_LIMITS_EXCEEDED"
	case MI_RESULT_SERVER_IS_SHUTTING_DOWN:
		return "MI_RESULT_SERVER_IS_SHUTTING_DOWN"
	default:
		return "MI_RESULT_UNKNOWN"
	}
}

type MI_Application struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *MI_ApplicationFT
}

type MI_ApplicationFT struct {
	Close                          uintptr
	NewSession                     func(application, protocol, destination, options, callbacks, extendedError, session uintptr) MI_Result
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

// MI_Session represents a session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/ns-mi-mi_session
type MI_Session struct {
	reserved1 uint64
	reserved2 uintptr
	FT        *MI_SessionFT
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
