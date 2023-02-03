package acl

import (
	"os"
	"path/filepath"
	"unsafe"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

func getEffectiveRightsForSid(oldAcl windows.Handle, sid *windows.SID) (uint32, error) {
	return api.GetEffectiveRightsFromAcl(oldAcl, sid)
}

func getEffectiveRightsForSidName(oldAcl windows.Handle, sidName string) (uint32, error) {
	sid, err := windows.StringToSid(sidName)
	if err != nil {
		return 0, err
	}

	return getEffectiveRightsForSid(oldAcl, sid)
}

func getAccessModeForRights(rights uint32) uint32 {
	var ret uint32

	if rights&PERM_READ == PERM_READ {
		ret |= 04
	}
	if rights&PERM_WRITE == PERM_WRITE {
		ret |= 02
	}
	if rights&PERM_EXECUTE == PERM_EXECUTE {
		ret |= 01
	}

	return ret
}

func GetExplicitAccessMode(name string) (os.FileMode, error) {
	var (
		oldAcl  windows.Handle
		secDesc windows.Handle

		owner *windows.SID
		group *windows.SID
	)

	path, err := filepath.Abs(name)
	if err != nil {
		return os.FileMode(0), err
	}

	err = api.GetNamedSecurityInfo(
		path,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|
			api.OWNER_SECURITY_INFORMATION|
			api.GROUP_SECURITY_INFORMATION,
		&owner,
		&group,
		&oldAcl,
		nil,
		&secDesc,
	)
	if err != nil {
		return os.FileMode(0), err
	}
	defer windows.LocalFree(secDesc)

	ownerName, err := owner.String()
	if err != nil {
		return os.FileMode(0), err
	}

	groupName, err := group.String()
	if err != nil {
		return os.FileMode(0), err
	}

	entries, err := api.GetExplicitEntriesFromAcl(oldAcl)
	if err != nil {
		return os.FileMode(0), err
	}

	var mode uint32
	if len(entries) > 0 {
		for _, item := range entries {
			if item.AccessMode == api.GRANT_ACCESS && item.Trustee.TrusteeForm == api.TRUSTEE_IS_SID {
				trustee := (*windows.SID)(unsafe.Pointer(item.Trustee.Name))

				name, err := trustee.String()
				if err != nil {
					continue
				}

				switch name {
				case ownerName:
					mode |= (getAccessModeForRights(item.AccessPermissions) << 6)
				case groupName:
					mode |= (getAccessModeForRights(item.AccessPermissions) << 3)
				case SID_NAME_EVERYONE:
					mode |= getAccessModeForRights(item.AccessPermissions)

				}
			}
		}
	}

	return os.FileMode(mode), nil
}

func GetEffectiveAccessMode(name string) (os.FileMode, error) {
	// get the file's current ACL
	var (
		oldAcl  windows.Handle
		secDesc windows.Handle

		owner *windows.SID
		group *windows.SID
	)

	path, err := filepath.Abs(name)
	if err != nil {
		return os.FileMode(0), err
	}

	err = api.GetNamedSecurityInfo(
		path,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|
			api.OWNER_SECURITY_INFORMATION|
			api.GROUP_SECURITY_INFORMATION,
		&owner,
		&group,
		&oldAcl,
		nil,
		&secDesc,
	)
	if err != nil {
		return os.FileMode(0), err
	}
	defer windows.LocalFree(secDesc)

	ownerRights, err := getEffectiveRightsForSid(oldAcl, owner)
	if err != nil {
		return os.FileMode(0), err
	}

	groupRights, err := getEffectiveRightsForSid(oldAcl, group)
	if err != nil {
		return os.FileMode(0), err
	}

	everyoneRights, err := getEffectiveRightsForSidName(oldAcl, SID_NAME_EVERYONE)
	if err != nil {
		return os.FileMode(0), err
	}

	mode := os.FileMode(
		getAccessModeForRights(ownerRights)<<6 |
			getAccessModeForRights(groupRights)<<3 |
			getAccessModeForRights(everyoneRights)<<0)

	return mode, nil
}
