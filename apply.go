package acl

import (
	"github.com/KuoKongQingYun/go-acl/api"
	"golang.org/x/sys/windows"

	"unsafe"
)

// Apply the provided access control entries to a file. If the replace
// parameter is true, existing entries will be overwritten. If the inherit
// parameter is true, the file will inherit ACEs from its parent.
func Apply(name string, replace, inherit bool, owner, group *windows.SID, entries ...api.ExplicitAccess) error {
	var oldACL windows.Handle
	if !replace {
		var secDesc windows.Handle
		api.GetNamedSecurityInfo(
			name,
			api.SE_FILE_OBJECT,
			api.DACL_SECURITY_INFORMATION,
			nil,
			nil,
			&oldACL,
			nil,
			&secDesc,
		)
		defer windows.LocalFree(secDesc)
	}
	var acl windows.Handle
	if err := api.SetEntriesInAcl(
		entries,
		oldACL,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(acl)))
	var secInfo uint32
	if !inherit {
		secInfo = api.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = api.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if owner != nil {
		secInfo |= api.OWNER_SECURITY_INFORMATION
	}
	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|secInfo,
		owner,
		group,
		acl,
		0,
	)
}
