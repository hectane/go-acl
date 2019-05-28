package acl

import (
	"golang.org/x/sys/windows"
)

const (
	SID_NAME_CREATOR_OWNER = "S-1-3-0"
	SID_NAME_CREATOR_GROUP = "S-1-3-1"
	SID_NAME_EVERYONE      = "S-1-1-0"
)

// access mask constants from https://docs.microsoft.com/en-us/windows/desktop/wmisdk/file-and-directory-access-rights-constants
// the x/sys/windows package defines some but not all of these constants
const FILE_READ_DATA = windows.FILE_LIST_DIRECTORY // for a directory, the ability to list contents
// the windows package only has this by the "LIST_DIRECTORY" name
const FILE_WRITE_DATA = 0x02                      // for a directory, the ability to add a file
const FILE_APPEND_DATA = windows.FILE_APPEND_DATA // for a directory, the ability to add a subdirectory
const FILE_READ_EA = 0x08
const FILE_WRITE_EA = 0x10
const FILE_EXECUTE = 0x20 // for a directory, the ability to traverse
const FILE_READ_ATTRIBUTES = 0x80
const FILE_WRITE_ATTRIBUTES = windows.FILE_WRITE_ATTRIBUTES
const DELETE = 0x10000
const SYNCHRONIZE = windows.SYNCHRONIZE

// these correspond to the GENERIC permissions from https://docs.microsoft.com/en-us/windows/desktop/FileIO/file-security-and-access-rights
// except that PERM_WRITE has DELETE added to it because otherwise it would be impossible to delete or rename a file.

const PERM_READ uint32 = 0 |
	FILE_READ_ATTRIBUTES |
	FILE_READ_DATA |
	FILE_READ_EA |
	windows.STANDARD_RIGHTS_READ |
	SYNCHRONIZE

const PERM_WRITE uint32 = 0 |
	FILE_APPEND_DATA |
	FILE_WRITE_ATTRIBUTES |
	FILE_WRITE_DATA |
	FILE_WRITE_EA |
	windows.STANDARD_RIGHTS_WRITE |
	SYNCHRONIZE

const PERM_EXECUTE uint32 = 0 |
	FILE_EXECUTE |
	FILE_READ_ATTRIBUTES |
	windows.STANDARD_RIGHTS_EXECUTE |
	SYNCHRONIZE
