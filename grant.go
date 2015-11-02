package acl

import (
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"unsafe"
)

// Grant permission for a file to the provided SIDs. The new access control
// entries will replace existing ones unless the replace parameter is false.
func Grant(name string, accessPermissions uint32, replace bool, sids ...*windows.SID) error {
	var oldAcl windows.Handle
	if !replace {
		var secDesc windows.Handle
		api.GetNamedSecurityInfo(
			name,
			api.SE_FILE_OBJECT,
			api.DACL_SECURITY_INFORMATION,
			nil,
			nil,
			&oldAcl,
			nil,
			&secDesc,
		)
		defer windows.LocalFree(secDesc)
	}
	var entries = make([]api.ExplicitAccess, len(sids))
	for i, sid := range sids {
		entries[i] = api.ExplicitAccess{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        api.GRANT_ACCESS,
			Inheritance:       api.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: api.Trustee{
				TrusteeForm: api.TRUSTEE_IS_SID,
				Name:        (*uint16)(unsafe.Pointer(sid)),
			},
		}
	}
	var acl windows.Handle
	if err := api.SetEntriesInAcl(
		entries,
		oldAcl,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(acl)))
	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		0,
	)
	return nil
}
