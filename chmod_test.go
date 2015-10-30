package acl

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestChmod(t *testing.T) {
	p, err := ioutil.TempDir(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(p)
	if err := Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(p)
	if err == nil {
		d.Close()
		t.Fatal("owner able to access directory")
	}
	if err := Chmod(p, 0400); err != nil {
		t.Fatal(err)
	}
	d, err = os.Open(p)
	if err != nil {
		t.Fatal("owner unable to access directory")
	}
	d.Close()
}
