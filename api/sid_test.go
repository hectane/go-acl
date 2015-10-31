package api

import (
	"testing"
)

func TestSIDLookup(t *testing.T) {
	_, err := CreateWellKnownSid(WinNullSid, nil)
	if err != nil {
		t.Fatal(err)
	}
}
