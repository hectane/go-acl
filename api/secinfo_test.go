package api

import (
	"golang.org/x/sys/windows"

	"io/ioutil"
	"os"
	"testing"
)

func TestGetNamedSecurityInfo(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	var (
		ownerSid *windows.SID
		secDesc  windows.Handle
	)
	if err = GetNamedSecurityInfo(
		f.Name(),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		&ownerSid,
		nil,
		nil,
		nil,
		&secDesc,
	); err != nil {
		t.Fatal(err)
	}
	defer windows.LocalFree(secDesc)
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid(ownerSid, u.User.Sid) {
		t.Fatal("SID of file does not match SID of current process")
	}
}

func TestSetNamedSecurityInfo(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err = SetNamedSecurityInfo(
		f.Name(),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		u.User.Sid,
		nil,
		0,
		0,
	); err != nil {
		t.Fatal(err)
	}
}
