package api

import (
	"golang.org/x/sys/windows"

	"unsafe"
)

const (
	SE_UNKNOWN_OBJECT_TYPE = iota
	SE_FILE_OBJECT
	SE_SERVICE
	SE_PRINTER
	SE_REGISTRY_KEY
	SE_LMSHARE
	SE_KERNEL_OBJECT
	SE_WINDOW_OBJECT
	SE_DS_OBJECT
	SE_DS_OBJECT_ALL
	SE_PROVIDER_DEFINED_OBJECT
	SE_WMIGUID_OBJECT
	SE_REGISTRY_WOW64_32KEY
)

const (
	OWNER_SECURITY_INFORMATION               = 0x00001
	GROUP_SECURITY_INFORMATION               = 0x00002
	DACL_SECURITY_INFORMATION                = 0x00004
	SACL_SECURITY_INFORMATION                = 0x00008
	LABEL_SECURITY_INFORMATION               = 0x00010
	ATTRIBUTE_SECURITY_INFORMATION           = 0x00020
	SCOPE_SECURITY_INFORMATION               = 0x00040
	PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00080
	BACKUP_SECURITY_INFORMATION              = 0x10000

	PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
	PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
	UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
	UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
)

var (
	procGetNamedSecurityInfoW = advapi32.MustFindProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfoW = advapi32.MustFindProc("SetNamedSecurityInfoW")
)

type ACL struct{}

// Retrieve information from the security descriptor for an object. Note that
// secDesc must be freed using windows.LocalFree().
func GetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner, group **windows.SID, dacl, sacl **ACL, secDesc *windows.Handle) error {
	ret, _, err := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(objectName))),
		uintptr(objectType),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(owner)),
		uintptr(unsafe.Pointer(group)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
		uintptr(unsafe.Pointer(secDesc)),
	)
	if ret != 0 {
		return err
	}
	return nil
}

// Set information in the security descriptor for an object.
func SetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner, group *windows.SID, dacl, sacl *ACL) error {
	ret, _, err := procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(objectName))),
		uintptr(objectType),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(owner)),
		uintptr(unsafe.Pointer(group)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
	)
	if ret != 0 {
		return err
	}
	return nil
}
