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
		entries = []api.ExplicitAccess{
			{
				AccessPermissions: (uint32(mode) & 0700) << 23,
				AccessMode:        api.GRANT_ACCESS,
				Inheritance:       api.NO_INHERITANCE,
				Trustee: api.Trustee{
					TrusteeForm: api.TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(sidOwner)),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0070) << 26,
				AccessMode:        api.GRANT_ACCESS,
				Inheritance:       api.NO_INHERITANCE,
				Trustee: api.Trustee{
					TrusteeForm: api.TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(sidGroup)),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0007) << 29,
				AccessMode:        api.GRANT_ACCESS,
				Inheritance:       api.NO_INHERITANCE,
				Trustee: api.Trustee{
					TrusteeForm: api.TRUSTEE_IS_SID,
					Name:        (*uint16)(unsafe.Pointer(sidWorld)),
				},
			},
		}
		acl windows.Handle
	)
	if err := api.SetEntriesInAcl(entries, 0, &acl); err != nil {
		return err
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(acl)))
	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|api.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		0,
	)
}
