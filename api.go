package acl

import (
	"golang.org/x/sys/windows"

	"unsafe"
)

const (
	ERROR_SUCCESS = 0
)

// SE_OBJECT_TYPE enumeration.
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

// SECURITY_INFORMATION constants.
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
	advapi32 = windows.MustLoadDLL("advapi32.dll")

	procGetNamedSecurityInfoW = advapi32.MustFindProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfoW = advapi32.MustFindProc("SetNamedSecurityInfoW")
)

type ACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

// Retrieve a copy of the security descriptor for the specified object. Note
// that ppSecurityDescriptor must be freed using windows.LocalFree().
func GetNamedSecurityInfo(pObjectName string, ObjectType int32, SecurityInfo uint32, ppsidOwner, ppsidGroup **windows.SID, ppDacl, ppSacl **ACL, ppSecurityDescriptor *windows.Handle) error {
	ret, _, err := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(pObjectName))),
		uintptr(ObjectType),
		uintptr(SecurityInfo),
		uintptr(unsafe.Pointer(ppsidOwner)),
		uintptr(unsafe.Pointer(ppsidGroup)),
		uintptr(unsafe.Pointer(ppDacl)),
		uintptr(unsafe.Pointer(ppSacl)),
		uintptr(unsafe.Pointer(ppSecurityDescriptor)),
	)
	if ret != ERROR_SUCCESS {
		return err
	}
	return nil
}

// Set the sepecified information in the object's security descriptor.
func SetNamedSecurityInfo(pObjectName string, ObjectType int32, SecurityInfo uint32, psidOwner, psidGroup *windows.SID, pDacl, pSacl *ACL) error {
	ret, _, err := procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(pObjectName))),
		uintptr(ObjectType),
		uintptr(SecurityInfo),
		uintptr(unsafe.Pointer(psidOwner)),
		uintptr(unsafe.Pointer(psidGroup)),
		uintptr(unsafe.Pointer(pDacl)),
		uintptr(unsafe.Pointer(pSacl)),
	)
	if ret != ERROR_SUCCESS {
		return err
	}
	return nil
}
