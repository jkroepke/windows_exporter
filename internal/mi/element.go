package mi

import (
	"errors"
)

func (e *Element) String() (string, error) {
	if e.valueType != ValueTypeCHAR16 && e.valueType != ValueTypeCHAR16A && e.valueType != ValueTypeSTRING && e.valueType != ValueTypeSTRINGA {
		return "", errors.New("element is not a string")
	}

	return "", nil

	/*

		value, ok := e.value.data.(*uint16)
		if !ok {
			return "", errors.New("element is not a string")
		}
		return windows.UTF16PtrToString(value), nil

	*/

}
