package acl

import (
	"golang.org/x/sys/windows"

	"os"
	"unsafe"
)

// Change the permissions of the specified file. Only the nine
// least-significant bytes are used, allowing access by the file's owner, the
// file's group, and any other user to be explicitly controlled.
func Chmod(name string, mode os.FileMode) error {
	var (
		sidOwner    = make([]byte, SECURITY_MAX_SID_SIZE)
		sidOwnerLen = uint32(SECURITY_MAX_SID_SIZE)
		sidGroup    = make([]byte, SECURITY_MAX_SID_SIZE)
		sidGroupLen = uint32(SECURITY_MAX_SID_SIZE)
		sidWorld    = make([]byte, SECURITY_MAX_SID_SIZE)
		sidWorldLen = uint32(SECURITY_MAX_SID_SIZE)
	)
	if err := CreateWellKnownSid(WinCreatorOwnerSid, nil, (*windows.SID)(unsafe.Pointer(&sidOwner[0])), &sidOwnerLen); err != nil {
		return err
	}
	if err := CreateWellKnownSid(WinCreatorGroupSid, nil, (*windows.SID)(unsafe.Pointer(&sidGroup[0])), &sidGroupLen); err != nil {
		return err
	}
	if err := CreateWellKnownSid(WinWorldSid, nil, (*windows.SID)(unsafe.Pointer(&sidWorld[0])), &sidWorldLen); err != nil {
		return err
	}
	var (
		entries = []ExplicitAccess{
			{
				AccessPermissions: (uint32(mode) & 0700) << 23,
				AccessMode:        GRANT_ACCESS,
				Inheritance:       NO_INHERITANCE,
				Trustee: Trustee{
					TrusteeForm: TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(&sidOwner[0])),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0070) << 26,
				AccessMode:        GRANT_ACCESS,
				Inheritance:       NO_INHERITANCE,
				Trustee: Trustee{
					TrusteeForm: TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(&sidGroup[0])),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0007) << 29,
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
	if err := SetEntriesInAcl(entries, nil, &acl); err != nil {
		return err
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(acl)))
	return SetNamedSecurityInfo(
		name,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}
