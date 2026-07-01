package injector

// #include "injector.h"
import "C"
import "fmt"

const (
	ErrSuccess          = int(C.INJERR_SUCCESS)
	ErrOther            = int(C.INJERR_OTHER)
	ErrNoMemory         = int(C.INJERR_NO_MEMORY)
	ErrNoProcess        = int(C.INJERR_NO_PROCESS)
	ErrNoLibrary        = int(C.INJERR_NO_LIBRARY)
	ErrErrorInTarget    = int(C.INJERR_ERROR_IN_TARGET)
	ErrFileNotFound     = int(C.INJERR_FILE_NOT_FOUND)
	ErrInvalidMemArea   = int(C.INJERR_INVALID_MEMORY_AREA)
	ErrPermission       = int(C.INJERR_PERMISSION)
	ErrUnsupportedTarget = int(C.INJERR_UNSUPPORTED_TARGET)
	ErrInvalidELF       = int(C.INJERR_INVALID_ELF_FORMAT)
	ErrWaitTracee       = int(C.INJERR_WAIT_TRACEE)
	ErrFunctionMissing  = int(C.INJERR_FUNCTION_MISSING)
	ErrTimeout          = int(C.INJERR_TIMEOUT)
)

type InjectorError struct {
	Code int
	Msg  string
}

func (e *InjectorError) Error() string {
	return fmt.Sprintf("injector error %d: %s", e.Code, e.Msg)
}

func checkErr(rc C.int, inj *C.injector_t) error {
	if rc == 0 {
		return nil
	}
	msg := C.GoString(C.injector_last_error(inj))
	return &InjectorError{Code: int(rc), Msg: msg}
}
