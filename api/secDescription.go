package api

import (
	"runtime"

	"golang.org/x/sys/windows"

	"unsafe"
)

const (
	SECURITY_DESCRIPTOR_REVISION = 1
)

var (
	procSetSecurityDescriptorOwnerW   = advapi32.MustFindProc("SetSecurityDescriptorOwnerW")
	procInitializeSecurityDescriptorW = advapi32.MustFindProc("InitializeSecurityDescriptorW")
)

type SECURITY_DESCRIPTOR struct{}

func MakeNewSecurityDescriptor() *SECURITY_DESCRIPTOR {
	var SECURITY_DESCRIPTOR_MIN_LENGTH uint32
	if runtime.GOARCH == `386` {
		SECURITY_DESCRIPTOR_MIN_LENGTH = 20
	} else if runtime.GOARCH == `amd64` {
		SECURITY_DESCRIPTOR_MIN_LENGTH = 40
	}
	return (*SECURITY_DESCRIPTOR)(unsafe.Pointer((&(make([]byte, SECURITY_DESCRIPTOR_MIN_LENGTH)[0]))))
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa378863(v=vs.85).aspx
func InitializeSecurityDescriptor(pSecurityDescriptor *SECURITY_DESCRIPTOR, dwRevision uint32) error {
	ret, _, err := procInitializeSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(pSecurityDescriptor)),
		SECURITY_DESCRIPTOR_REVISION,
	)
	if ret != 0 {
		return err
	}
	return nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379585(v=vs.85).aspx
func SetSecurityDescriptorOwner(pSecurityDescriptor *SECURITY_DESCRIPTOR, owner *windows.SID, dacl, bOwnerDefaulted bool) error {
	var _bOwnerDefaulted int32
	if bOwnerDefaulted {
		_bOwnerDefaulted = 1
	} else {
		_bOwnerDefaulted = 0
	}
	ret, _, err := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pSecurityDescriptor)),
		uintptr(unsafe.Pointer(owner)),
		uintptr(_bOwnerDefaulted),
	)
	if ret != 0 {
		return err
	}
	return nil
}
