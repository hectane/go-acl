//+build windows

package api

import (
	"golang.org/x/sys/windows"

	"unsafe"
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379284.aspx
const (
	NO_MULTIPLE_TRUSTEE = iota
	TRUSTEE_IS_IMPERSONATE
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379638.aspx
const (
	TRUSTEE_IS_SID = iota
	TRUSTEE_IS_NAME
	TRUSTEE_BAD_FORM
	TRUSTEE_IS_OBJECTS_AND_SID
	TRUSTEE_IS_OBJECTS_AND_NAME
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379639.aspx
const (
	TRUSTEE_IS_UNKNOWN = iota
	TRUSTEE_IS_USER
	TRUSTEE_IS_GROUP
	TRUSTEE_IS_DOMAIN
	TRUSTEE_IS_ALIAS
	TRUSTEE_IS_WELL_KNOWN_GROUP
	TRUSTEE_IS_DELETED
	TRUSTEE_IS_INVALID
	TRUSTEE_IS_COMPUTER
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374899.aspx
const (
	NOT_USED_ACCESS = iota
	GRANT_ACCESS
	SET_ACCESS
	DENY_ACCESS
	REVOKE_ACCESS
	SET_AUDIT_SUCCESS
	SET_AUDIT_FAILURE
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446627.aspx
const (
	NO_INHERITANCE                     = 0x0
	SUB_OBJECTS_ONLY_INHERIT           = 0x1
	SUB_CONTAINERS_ONLY_INHERIT        = 0x2
	SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3
	INHERIT_NO_PROPAGATE               = 0x4
	INHERIT_ONLY                       = 0x8

	OBJECT_INHERIT_ACE       = 0x1
	CONTAINER_INHERIT_ACE    = 0x2
	NO_PROPAGATE_INHERIT_ACE = 0x4
	INHERIT_ONLY_ACE         = 0x8
)

var (
	procSetEntriesInAclW           = advapi32.MustFindProc("SetEntriesInAclW")
	procGetEffectiveRightsFromAclW = advapi32.MustFindProc("GetEffectiveRightsFromAclW")
	procGetExplicitEntriesFromAclW = advapi32.MustFindProc("GetExplicitEntriesFromAclW")
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379636.aspx
type Trustee struct {
	MultipleTrustee          *Trustee
	MultipleTrusteeOperation int32
	TrusteeForm              int32
	TrusteeType              int32
	Name                     *uint16
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446627.aspx
type ExplicitAccess struct {
	AccessPermissions uint32
	AccessMode        int32
	Inheritance       uint32
	Trustee           Trustee
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379576.aspx
func SetEntriesInAcl(entries []ExplicitAccess, oldAcl windows.Handle, newAcl *windows.Handle) error {
	ret, _, _ := procSetEntriesInAclW.Call(
		uintptr(len(entries)),
		uintptr(unsafe.Pointer(&entries[0])),
		uintptr(oldAcl),
		uintptr(unsafe.Pointer(newAcl)),
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}

func GetEffectiveRightsFromAcl(oldAcl windows.Handle, sid *windows.SID) (uint32, error) {
	trustee := Trustee{
		TrusteeForm: TRUSTEE_IS_SID,
		Name:        (*uint16)(unsafe.Pointer(sid)),
	}

	var rights uint32

	ret, _, err := procGetEffectiveRightsFromAclW.Call(
		uintptr(oldAcl),
		uintptr(unsafe.Pointer(&trustee)),
		uintptr(unsafe.Pointer(&rights)),
	)

	if ret != 0 {
		return 0, err
	}
	return rights, nil
}

func GetExplicitEntriesFromAcl(oldAcl windows.Handle) ([]ExplicitAccess, error) {
	var (
		count uint32
		list  uintptr
	)

	/* TODO: seems like I ought to be able to something like this:
	     var entries *[]ExplicitAccess
	     ret, _, err := procGetExplicitEntriesFromAclW.Call(
	         ...,
	         uintptr(unsafe.Pointer(&entries)),
	     )
	   but I couldn't figure out how to make it work.  I tried a whole
	   bunch of different combinations but I only ever managed to get an empty list
	*/
	ret, _, err := procGetExplicitEntriesFromAclW.Call(
		uintptr(oldAcl),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&list)),
	)

	if ret != 0 {
		return []ExplicitAccess{}, err
	}

	defer windows.LocalFree(windows.Handle(unsafe.Pointer(list)))

	explicitAccessSize := unsafe.Sizeof(ExplicitAccess{})
	getEntryAtOffset := func(list uintptr, offset uint32) ExplicitAccess {
		return *(*ExplicitAccess)(unsafe.Pointer(list + explicitAccessSize*uintptr(offset)))
	}

	output := make([]ExplicitAccess, count)
	for i := uint32(0); i < count; i++ {
		output[i] = getEntryAtOffset(list, i)
	}

	return output, nil
}
