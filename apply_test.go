//+build windows

package acl

import (
	"golang.org/x/sys/windows"

	"errors"
	"io/ioutil"
	"os"
	"testing"
)

func TestApply(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if err := Apply(
		f.Name(),
		true,
		true,
		DenyName(windows.GENERIC_ALL, "CREATOR OWNER"),
	); err != nil {
		t.Fatal(err)
	}
	r, err := os.Open(f.Name())
	if err == nil {
		r.Close()
		t.Fatal("owner able to access file")
	}
}

func TestError(t *testing.T) {
	if _, err := os.Stat(`C:\Folder\That\Doesnt\Exist`); !os.IsNotExist(err) {
		t.Skip(`Oh come on - C:\Folder\That\Doesnt\Exist exists`)
	}

	err := Apply(
		`C:\Folder\That\Doesnt\Exist`,
		true,
		true,
		DenyName(windows.GENERIC_ALL, "CREATOR OWNER"),
	)
	if err == nil {
		t.Fatal("Error expected, none received")
	}
	t.Log(err)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Expected to receive an error that \"Is\" ErrNotExist, received %s", err)
	}
}
