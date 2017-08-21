package acl

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/KuoKongQingYun/go-acl/api"

	"golang.org/x/sys/windows"
)

func TestApply(t *testing.T) {
	var (
		sid    = make([]byte, api.SECURITY_MAX_SID_SIZE)
		sidLen = uint32(unsafe.Sizeof(sid))
	)
	err := api.CreateWellKnownSid(
		api.WinBuiltinAdministratorsSid,
		nil,
		(*windows.SID)(unsafe.Pointer(&sid[0])),
		&sidLen,
	)
	fmt.Println(err)
	fmt.Println(sid)
	fmt.Println(sidLen)
	if err := Apply(
		`C:\Windows\System32\drivers\usbser.sys`,
		true,
		true,
		(*windows.SID)(unsafe.Pointer(&sid[0])),
		(*windows.SID)(unsafe.Pointer(&sid[0])),
		GrantName(windows.GENERIC_ALL, "CREATOR OWNER"),
	); err != nil {
		fmt.Println(err)
		t.Fatal(err)
	}
}
