package mi

import (
	"errors"

	"golang.org/x/sys/windows"
)

var (
	localhost = UTF16PtrFromString[*uint16]("localhost")
)

type QueryDialect = *uint16

var (
	QueryDialectWQL = UTF16PtrFromString[QueryDialect]("WQL")
	QueryDialectCQL = UTF16PtrFromString[QueryDialect]("CQL")
)

type Protocol = *uint16

var (
	ProtocolWINRM   = UTF16PtrFromString[Protocol]("WINRM")
	ProtocolWMIDCOM = UTF16PtrFromString[Protocol]("WMIDCOM")
)

type Namespace = *uint16

var (
	NamespaceRootCIMv2 = UTF16PtrFromString[Namespace]("root/cimv2")
)

func UTF16PtrFromString[T *uint16](s string) T {
	val, err := windows.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}

	return val
}

// OperationFlags represents the flags for an operation.
// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmi_v2/mi-flags
type OperationFlags uint32

const (
	OperationNoFlags           OperationFlags = 0x0000
	OperationFlagsBasicRTTI    OperationFlags = 0x0002
	OperationFlagsNoRTTI                      = 0x0400
	OperationFlagsStandardRTTI                = 0x0800
)

type Result uint32

const (
	MI_RESULT_OK Result = iota
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

func (r Result) Error() string {
	return r.String()
}

func (r Result) String() string {
	switch {
	case errors.Is(r, MI_RESULT_OK):
		return "MI_RESULT_OK"
	case errors.Is(r, MI_RESULT_FAILED):
		return "MI_RESULT_FAILED"
	case errors.Is(r, MI_RESULT_ACCESS_DENIED):
		return "MI_RESULT_ACCESS_DENIED"
	case errors.Is(r, MI_RESULT_INVALID_NAMESPACE):
		return "MI_RESULT_INVALID_NAMESPACE"
	case errors.Is(r, MI_RESULT_INVALID_PARAMETER):
		return "MI_RESULT_INVALID_PARAMETER"
	case errors.Is(r, MI_RESULT_INVALID_CLASS):
		return "MI_RESULT_INVALID_CLASS"
	case errors.Is(r, MI_RESULT_NOT_FOUND):
		return "MI_RESULT_NOT_FOUND"
	case errors.Is(r, MI_RESULT_NOT_SUPPORTED):
		return "MI_RESULT_NOT_SUPPORTED"
	case errors.Is(r, MI_RESULT_CLASS_HAS_CHILDREN):
		return "MI_RESULT_CLASS_HAS_CHILDREN"
	case errors.Is(r, MI_RESULT_CLASS_HAS_INSTANCES):
		return "MI_RESULT_CLASS_HAS_INSTANCES"
	case errors.Is(r, MI_RESULT_INVALID_SUPERCLASS):
		return "MI_RESULT_INVALID_SUPERCLASS"
	case errors.Is(r, MI_RESULT_ALREADY_EXISTS):
		return "MI_RESULT_ALREADY_EXISTS"
	case errors.Is(r, MI_RESULT_NO_SUCH_PROPERTY):
		return "MI_RESULT_NO_SUCH_PROPERTY"
	case errors.Is(r, MI_RESULT_TYPE_MISMATCH):
		return "MI_RESULT_TYPE_MISMATCH"
	case errors.Is(r, MI_RESULT_QUERY_LANGUAGE_NOT_SUPPORTED):
		return "MI_RESULT_QUERY_LANGUAGE_NOT_SUPPORTED"
	case errors.Is(r, MI_RESULT_INVALID_QUERY):
		return "MI_RESULT_INVALID_QUERY"
	case errors.Is(r, MI_RESULT_METHOD_NOT_AVAILABLE):
		return "MI_RESULT_METHOD_NOT_AVAILABLE"
	case errors.Is(r, MI_RESULT_METHOD_NOT_FOUND):
		return "MI_RESULT_METHOD_NOT_FOUND"
	case errors.Is(r, MI_RESULT_NAMESPACE_NOT_EMPTY):
		return "MI_RESULT_NAMESPACE_NOT_EMPTY"
	case errors.Is(r, MI_RESULT_INVALID_ENUMERATION_CONTEXT):
		return "MI_RESULT_INVALID_ENUMERATION_CONTEXT"
	case errors.Is(r, MI_RESULT_INVALID_OPERATION_TIMEOUT):
		return "MI_RESULT_INVALID_OPERATION_TIMEOUT"
	case errors.Is(r, MI_RESULT_PULL_HAS_BEEN_ABANDONED):
		return "MI_RESULT_PULL_HAS_BEEN_ABANDONED"
	case errors.Is(r, MI_RESULT_PULL_CANNOT_BE_ABANDONED):
		return "MI_RESULT_PULL_CANNOT_BE_ABANDONED"
	case errors.Is(r, MI_RESULT_FILTERED_ENUMERATION_NOT_SUPPORTED):
		return "MI_RESULT_FILTERED_ENUMERATION_NOT_SUPPORTED"
	case errors.Is(r, MI_RESULT_CONTINUATION_ON_ERROR_NOT_SUPPORTED):
		return "MI_RESULT_CONTINUATION_ON_ERROR_NOT_SUPPORTED"
	case errors.Is(r, MI_RESULT_SERVER_LIMITS_EXCEEDED):
		return "MI_RESULT_SERVER_LIMITS_EXCEEDED"
	case errors.Is(r, MI_RESULT_SERVER_IS_SHUTTING_DOWN):
		return "MI_RESULT_SERVER_IS_SHUTTING_DOWN"
	default:
		return "MI_RESULT_UNKNOWN"
	}
}

type Application struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *ApplicationFT
}

type ApplicationFT struct {
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

// Session represents a session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/ns-mi-mi_session
type Session struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *SessionFT
}

// SessionFT represents the function table for Session.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/ns-mi-mi_session
type SessionFT struct {
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

// Operation represents an operation.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/ns-mi-mi_operation
type Operation struct {
	reserved1 uint64
	reserved2 uintptr
	ft        *OperationFT
}

// OperationFT represents the function table for Operation.
// https://learn.microsoft.com/en-us/windows/win32/api/mi/ns-mi-mi_operationft
type OperationFT struct {
	Close         uintptr
	Cancel        uintptr
	GetSession    uintptr
	GetInstance   uintptr
	GetIndication uintptr
	GetClass      uintptr
}

type Instance struct {
	ft         *InstanceFT
	classDecl  *ClassDecl
	serverName *uint16
	nameSpace  *uint16
	_          [4]uintptr
}

type InstanceFT struct {
	Close           uintptr
	Destruct        uintptr
	IsA             uintptr
	GetClassName    uintptr
	SetNameSpace    uintptr
	GetNameSpace    uintptr
	GetElementCount uintptr
	AddElement      uintptr
	SetElement      uintptr
	SetElementAt    uintptr
	GetElement      uintptr
	GetElementAt    uintptr
	ClearElement    uintptr
	ClearElementAt  uintptr
	GetServerName   uintptr
	GetClass        uintptr
}

type SessionCallbacks struct {
	ctx          uintptr
	writeMessage uintptr
	writeError   uintptr
}

type OperationCallbacks struct {
	ctx                     uintptr
	promptUser              uintptr
	writeError              uintptr
	writeMessage            uintptr
	writeProgress           uintptr
	instanceResult          uintptr
	indicationResult        uintptr
	classResult             uintptr
	streamedParameterResult uintptr
}

type ClassDecl struct {
	flags          uint32
	code           uint32
	name           *uint16
	Mqualifiers    uintptr
	numQualifiers  uint32
	Mproperties    []*PropertyDecl
	numProperties  uint32
	size           uint32
	superClass     *uint16
	superClassDecl uintptr
	methods        uintptr
	numMethods     uint32

	schema      uintptr
	providerFT  uintptr
	owningClass uintptr
}

type Qualifier struct {
	name          *uint16
	qualifierType uint32
	flavor        uint32
	value         *uint16
}

type PropertyDecl struct {
	flags         uint32
	code          uint32
	name          *uint16
	Mqualifiers   uintptr
	numQualifiers uint32
	propertyType  uint32
	className     *uint16
	subscript     uint32
	offset        uint32
	origin        *uint16
	propagator    *uint16
	value         uintptr
}

type Class struct {
	ft *ClassFT

	classDecl     uintptr
	namespaceName *uint16
	serverName    *uint16
	_             [4]uintptr
}

type ClassFT struct {
	GetClassName         uintptr
	GetNameSpace         uintptr
	GetServerName        uintptr
	GetElementCount      uintptr
	GetElement           uintptr
	GetElementAt         uintptr
	GetClassQualifierSet uintptr
	GetMethodCount       uintptr
	GetMethodAt          uintptr
	GetMethod            uintptr
	GetParentClassName   uintptr
	GetParentClass       uintptr
	Delete               uintptr
	Clone                uintptr
}

type Element struct {
	value     *Value
	valueType ValueType
	index     uint32
	flags     uint32
}

type Value struct {
	boolean  uint8
	uint8    uint8
	sint8    int8
	uint16   uint16
	sint16   int16
	uint32   uint32
	sint32   int32
	uint64   uint64
	sint64   int64
	real32   float32
	real64   float64
	char16   uint16
	datetime struct {
		isTimestamp uint32
		u           struct {
			timestamp Timestamp
			interval  Interval
		}
	}
	string    *uint16
	instance  *Instance
	reference *Instance
	booleana  struct {
		data uintptr
		size uint32
	}
	uint8a struct {
		data uintptr
		size uint32
	}
	sint8a struct {
		data uintptr
		size uint32
	}
	uint16a struct {
		data uintptr
		size uint32
	}
	sint16a struct {
		data uintptr
		size uint32
	}
	uint32a struct {
		data uintptr
		size uint32
	}
	sint32a struct {
		data uintptr
		size uint32
	}
	uint64a struct {
		data uintptr
		size uint32
	}
	sint64a struct {
		data uintptr
		size uint32
	}
	real32a struct {
		data uintptr
		size uint32
	}
	real64a struct {
		data uintptr
		size uint32
	}
	char16a struct {
		data uintptr
		size uint32
	}
	datetimea struct {
		data uintptr
		size uint32
	}
	stringa struct {
		data uintptr
		size uint32
	}
	referencea struct {
		data **Instance
		size uint32
	}
	instancea struct {
		data **Instance
		size uint32
	}
	array struct {
		data []byte
		size uint32
	}
}

type ValueType uint32

const (
	ValueTypeBOOLEAN    = 0
	ValueTypeUINT8      = 1
	ValueTypeSINT8      = 2
	ValueTypeUINT16     = 3
	ValueTypeSINT16     = 4
	ValueTypeUINT32     = 5
	ValueTypeSINT32     = 6
	ValueTypeUINT64     = 7
	ValueTypeSINT64     = 8
	ValueTypeREAL32     = 9
	ValueTypeREAL64     = 10
	ValueTypeCHAR16     = 11
	ValueTypeDATETIME   = 12
	ValueTypeSTRING     = 13
	ValueTypeREFERENCE  = 14
	ValueTypeINSTANCE   = 15
	ValueTypeBOOLEANA   = 16
	ValueTypeUINT8A     = 17
	ValueTypeSINT8A     = 18
	ValueTypeUINT16A    = 19
	ValueTypeSINT16A    = 20
	ValueTypeUINT32A    = 21
	ValueTypeSINT32A    = 22
	ValueTypeUINT64A    = 23
	ValueTypeSINT64A    = 24
	ValueTypeREAL32A    = 25
	ValueTypeREAL64A    = 26
	ValueTypeCHAR16A    = 27
	ValueTypeDATETIMEA  = 28
	ValueTypeSTRINGA    = 29
	ValueTypeREFERENCEA = 30
	ValueTypeINSTANCEA  = 31
	ValueTypeARRAY      = 16
)

type Timestamp struct {
	year         uint32
	month        uint32
	day          uint32
	hour         uint32
	minute       uint32
	second       uint32
	microseconds uint32
	utc          int32
}

type Interval struct {
	days         uint32
	hours        uint32
	minutes      uint32
	seconds      uint32
	microseconds uint32
	__padding1   uint32
	__padding2   uint32
	__padding3   uint32
}
