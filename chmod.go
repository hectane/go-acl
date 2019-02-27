package acl

import (
	"os"

	"golang.org/x/sys/windows"
)

// Change the permissions of the specified file. Only the nine
// least-significant bytes are used, allowing access by the file's owner, the
// file's group, and everyone else to be explicitly controlled.
func Chmod(name string, mode os.FileMode) error {
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	creatorOwnerSID, err := windows.StringToSid("S-1-3-0")
	if err != nil {
		return err
	}
	creatorGroupSID, err := windows.StringToSid("S-1-3-1")
	if err != nil {
		return err
	}
	everyoneSID, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		return err
	}

	return Apply(
		name,
		true,
		false,
		GrantSid((uint32(mode)&0700)<<23, creatorOwnerSID),
		GrantSid((uint32(mode)&0070)<<26, creatorGroupSID),
		GrantSid((uint32(mode)&0007)<<29, everyoneSID),
	)
}
