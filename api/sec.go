package api

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSetFileSecurityW = advapi32.MustFindProc("SetFileSecurityW")
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379576.aspx
func SetFileSecurity(lpFileName string, SecurityInformation uint32, pSecurityDescriptor *SECURITY_DESCRIPTOR) error {
	ret, _, err := procSetEntriesInAclW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(lpFileName))),
		uintptr(SecurityInformation),
		uintptr(unsafe.Pointer(pSecurityDescriptor)),
	)
	if ret != 0 {
		return err
	}
	return nil
}
