package acl

import (
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"os"
	"unsafe"
)

// Change the permissions of the specified file. Only the nine
// least-significant bytes are used, allowing access by the file's owner, the
// file's group, and any other user to be explicitly controlled.
func Chmod(name string, mode os.FileMode) error {
	sidOwner, err := api.CreateWellKnownSid(api.WinCreatorOwnerSid, nil)
	if err != nil {
		return err
	}
	sidGroup, err := api.CreateWellKnownSid(api.WinCreatorGroupSid, nil)
	if err != nil {
		return err
	}
	sidWorld, err := api.CreateWellKnownSid(api.WinWorldSid, nil)
	if err != nil {
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
					Name:        (*uint16)(unsafe.Pointer(sidOwner)),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0070) << 26,
				AccessMode:        GRANT_ACCESS,
				Inheritance:       NO_INHERITANCE,
				Trustee: Trustee{
					TrusteeForm: TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(sidGroup)),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0007) << 29,
				AccessMode:        GRANT_ACCESS,
				Inheritance:       NO_INHERITANCE,
				Trustee: Trustee{
					TrusteeForm: TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(sidWorld)),
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
