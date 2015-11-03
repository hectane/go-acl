package acl

import (
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"unsafe"
)

// Apply the provided access control entries to a file. If the replace
// parameter is true, existing entries will be overwritten.
func Apply(name string, replace bool, entries ...api.ExplicitAccess) error {
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
}
