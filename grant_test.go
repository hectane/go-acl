package acl

import (
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"io/ioutil"
	"os"
	"testing"
)

func TestGrant(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if err := Grant(
		f.Name(),
		true,
		api.ExplicitAccess{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        api.DENY_ACCESS,
			Inheritance:       api.NO_INHERITANCE,
			Trustee: api.Trustee{
				TrusteeForm: api.TRUSTEE_IS_NAME,
				Name:        windows.StringToUTF16Ptr("CREATOR OWNER"),
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	r, err := os.Open(f.Name())
	if err == nil {
		r.Close()
		t.Fatal("owner able to access file")
	}
}
