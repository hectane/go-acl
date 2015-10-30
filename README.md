## go-acl

Manipulating ACLs (Access Control Lists) on Windows is difficult. go-acl wraps the Windows API functions that control access to objects, simplifying the process.

### Examples

Probably the most commonly used function in this package is `Chmod`:

    import "github.com/hectane/go-acl"

    err := acl.Chmod("C:\\path\\to\\file.txt", 0755)
    if err != nil {
        panic(err)
    }

### Using the API Directly

go-acl exposes the individual Windows API functions that are used to manipulate ACLs. For example, to retrieve the current owner of a file:

    var (
        owner   *windows.SID
        secDesc windows.Handle
    )
    err := acl.GetNamedSecurityInfo(
        "C:\\path\\to\\file.txt",
        acl.SE_FILE_OBJECT,
        acl.OWNER_SECURITY_INFORMATION,
        &owner,
        nil,
        nil,
        nil,
        &secDesc,
    )
    if err != nil {
        panic(err)
    }
    defer windows.LocalFree(secDesc)

`owner` will then point to the SID for the owner of the file.
