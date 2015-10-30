package acl

import (
	"golang.org/x/sys/windows"

	"os"
	"unsafe"
)

// Change the permissions of the specified object. Only the nine
// least-significant bytes are used, allowing access by the object's owner, the
// object's group, and any user to be explicitly controlled. The execute bit is
// always ignored since it has no meaning on Windows.
func Chmod(object string, mode os.FileMode) error {
	var (
		sidOwner    = make([]byte, SECURITY_MAX_SID_SIZE)
		sidOwnerLen = uint32(SECURITY_MAX_SID_SIZE)
		sidGroup    = make([]byte, SECURITY_MAX_SID_SIZE)
		sidGroupLen = uint32(SECURITY_MAX_SID_SIZE)
		sidWorld    = make([]byte, SECURITY_MAX_SID_SIZE)
		sidWorldLen = uint32(SECURITY_MAX_SID_SIZE)
	)
	err := CreateWellKnownSid(WinCreatorOwnerSid, nil, (*windows.SID)(unsafe.Pointer(&sidOwner[0])), &sidOwnerLen)
	if err != nil {
		return err
	}
	err = CreateWellKnownSid(WinCreatorGroupSid, nil, (*windows.SID)(unsafe.Pointer(&sidGroup[0])), &sidGroupLen)
	if err != nil {
		return err
	}
	err = CreateWellKnownSid(WinWorldSid, nil, (*windows.SID)(unsafe.Pointer(&sidWorld[0])), &sidWorldLen)
	if err != nil {
		return err
	}
	var (
		entries = []ExplicitAccess{
			{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        GRANT_ACCESS,
				Inheritance:       NO_INHERITANCE,
				Trustee: Trustee{
					TrusteeForm: TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(&sidOwner[0])),
				},
			},
			{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        GRANT_ACCESS,
				Inheritance:       NO_INHERITANCE,
				Trustee: Trustee{
					TrusteeForm: TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(&sidGroup[0])),
				},
			},
			{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        GRANT_ACCESS,
				Inheritance:       NO_INHERITANCE,
				Trustee: Trustee{
					TrusteeForm: TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(&sidWorld[0])),
				},
			},
		}
		acl *ACL
	)
	err = SetEntriesInAcl(entries, nil, &acl)
	if err != nil {
		return err
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(acl)))
	return SetNamedSecurityInfo(
		object,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}
