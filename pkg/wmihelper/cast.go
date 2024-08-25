package wmihelper

import (
	"fmt"
	"reflect"

	cim "github.com/microsoft/wmi/pkg/wmiinstance"
)

func CastInstances[S []E, E any](instances []*cim.WmiInstance, dst *S) error {
	for i, instance := range instances {
		var elm E

		if err := CastInstance(instance, &elm); err != nil {
			return fmt.Errorf("cannot convert instance %d to struct: %v", i, err)
		}

		*dst = append(*dst, elm)
	}

	return nil
}

func CastInstance[E any](instance *cim.WmiInstance, dst *E) error {
	// Reflect value of the second struct
	ssValue := reflect.ValueOf(dst).Elem()
	ssType := ssValue.Type()

	// Iterate over the fields of the second struct
	for i := 0; i < ssValue.NumField(); i++ {
		field := ssType.Field(i)
		fieldValue := ssValue.Field(i)

		// Get the property value from the first struct
		propValue, err := instance.GetProperty(field.Name)
		if err != nil {
			return fmt.Errorf("cannot get property %s: %v", field.Name, err)
		}
		if propValue == nil {
			continue
		}

		// Set the field value with the appropriate type conversion
		propValueReflect := reflect.ValueOf(propValue)
		if propValueReflect.Type().ConvertibleTo(fieldValue.Type()) {
			fieldValue.Set(propValueReflect.Convert(fieldValue.Type()))
		} else {
			return fmt.Errorf("cannot convert %v to %v", propValueReflect.Type(), fieldValue.Type())
		}
	}

	return nil
}
