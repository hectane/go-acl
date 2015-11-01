package acl

import (
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"os"
	"unsafe"
)

// Change the permissions of the specified file. Only the nine
// least-significant bytes are used, allowing access by the file's owner, the
// file's group, and everyone else to be explicitly controlled.
func Chmod(name string, mode os.FileMode) error {
	var (
		entries = []api.ExplicitAccess{
			{
				AccessPermissions: (uint32(mode) & 0700) << 23,
				AccessMode:        api.GRANT_ACCESS,
				Inheritance:       api.NO_INHERITANCE,
				Trustee: api.Trustee{
					TrusteeForm: api.TRUSTEE_IS_NAME,
					Name:        windows.StringToUTF16Ptr("CREATOR OWNER"),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0070) << 26,
				AccessMode:        api.GRANT_ACCESS,
				Inheritance:       api.NO_INHERITANCE,
				Trustee: api.Trustee{
					TrusteeForm: api.TRUSTEE_IS_NAME,
					Name:        windows.StringToUTF16Ptr("CREATOR GROUP"),
				},
			},
			{
				AccessPermissions: (uint32(mode) & 0007) << 29,
				AccessMode:        api.GRANT_ACCESS,
				Inheritance:       api.NO_INHERITANCE,
				Trustee: api.Trustee{
					TrusteeForm: api.TRUSTEE_IS_NAME,
					Name:        windows.StringToUTF16Ptr("EVERYONE"),
				},
			},
		}
		acl windows.Handle
	)
	if err := api.SetEntriesInAcl(
		entries,
		0,
		&acl,
	); err != nil {
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
