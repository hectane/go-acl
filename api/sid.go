package api

import (
	"golang.org/x/sys/windows"

	"unsafe"
)

const (
	SECURITY_MAX_SID_SIZE = 68
)

const (
	WinNullSid                                  = 0
	WinWorldSid                                 = 1
	WinLocalSid                                 = 2
	WinCreatorOwnerSid                          = 3
	WinCreatorGroupSid                          = 4
	WinCreatorOwnerServerSid                    = 5
	WinCreatorGroupServerSid                    = 6
	WinNtAuthoritySid                           = 7
	WinDialupSid                                = 8
	WinNetworkSid                               = 9
	WinBatchSid                                 = 10
	WinInteractiveSid                           = 11
	WinServiceSid                               = 12
	WinAnonymousSid                             = 13
	WinProxySid                                 = 14
	WinEnterpriseControllersSid                 = 15
	WinSelfSid                                  = 16
	WinAuthenticatedUserSid                     = 17
	WinRestrictedCodeSid                        = 18
	WinTerminalServerSid                        = 19
	WinRemoteLogonIdSid                         = 20
	WinLogonIdsSid                              = 21
	WinLocalSystemSid                           = 22
	WinLocalServiceSid                          = 23
	WinNetworkServiceSid                        = 24
	WinBuiltinDomainSid                         = 25
	WinBuiltinAdministratorsSid                 = 26
	WinBuiltinUsersSid                          = 27
	WinBuiltinGuestsSid                         = 28
	WinBuiltinPowerUsersSid                     = 29
	WinBuiltinAccountOperatorsSid               = 30
	WinBuiltinSystemOperatorsSid                = 31
	WinBuiltinPrintOperatorsSid                 = 32
	WinBuiltinBackupOperatorsSid                = 33
	WinBuiltinReplicatorSid                     = 34
	WinBuiltinPreWindows2000CompatibleAccessSid = 35
	WinBuiltinRemoteDesktopUsersSid             = 36
	WinBuiltinNetworkConfigurationOperatorsSid  = 37
	WinAccountAdministratorSid                  = 38
	WinAccountGuestSid                          = 39
	WinAccountKrbtgtSid                         = 40
	WinAccountDomainAdminsSid                   = 41
	WinAccountDomainUsersSid                    = 42
	WinAccountDomainGuestsSid                   = 43
	WinAccountComputersSid                      = 44
	WinAccountControllersSid                    = 45
	WinAccountCertAdminsSid                     = 46
	WinAccountSchemaAdminsSid                   = 47
	WinAccountEnterpriseAdminsSid               = 48
	WinAccountPolicyAdminsSid                   = 49
	WinAccountRasAndIasServersSid               = 50
	WinNTLMAuthenticationSid                    = 51
	WinDigestAuthenticationSid                  = 52
	WinSChannelAuthenticationSid                = 53
	WinThisOrganizationSid                      = 54
	WinOtherOrganizationSid                     = 55
	WinBuiltinIncomingForestTrustBuildersSid    = 56
	WinBuiltinPerfMonitoringUsersSid            = 57
	WinBuiltinPerfLoggingUsersSid               = 58
	WinBuiltinAuthorizationAccessSid            = 59
	WinBuiltinTerminalServerLicenseServersSid   = 60
	WinBuiltinDCOMUsersSid                      = 61
	WinBuiltinIUsersSid                         = 62
	WinIUserSid                                 = 63
	WinBuiltinCryptoOperatorsSid                = 64
	WinUntrustedLabelSid                        = 65
	WinLowLabelSid                              = 66
	WinMediumLabelSid                           = 67
	WinHighLabelSid                             = 68
	WinSystemLabelSid                           = 69
	WinWriteRestrictedCodeSid                   = 70
	WinCreatorOwnerRightsSid                    = 71
	WinCacheablePrincipalsGroupSid              = 72
	WinNonCacheablePrincipalsGroupSid           = 73
	WinEnterpriseReadonlyControllersSid         = 74
	WinAccountReadonlyControllersSid            = 75
	WinBuiltinEventLogReadersGroup              = 76
	WinNewEnterpriseReadonlyControllersSid      = 77
	WinBuiltinCertSvcDComAccessGroup            = 78
	WinMediumPlusLabelSid                       = 79
	WinLocalLogonSid                            = 80
	WinConsoleLogonSid                          = 81
	WinThisOrganizationCertificateSid           = 82
	WinApplicationPackageAuthoritySid           = 83
	WinBuiltinAnyPackageSid                     = 84
	WinCapabilityInternetClientSid              = 85
	WinCapabilityInternetClientServerSid        = 86
	WinCapabilityPrivateNetworkClientServerSid  = 87
	WinCapabilityPicturesLibrarySid             = 88
	WinCapabilityVideosLibrarySid               = 89
	WinCapabilityMusicLibrarySid                = 90
	WinCapabilityDocumentsLibrarySid            = 91
	WinCapabilitySharedUserCertificatesSid      = 92
	WinCapabilityEnterpriseAuthenticationSid    = 93
	WinCapabilityRemovableStorageSid            = 94
)

const (
	SidTypeUser = iota + 1
	SidTypeGroup
	SidTypeDomain
	SidTypeAlias
	SidTypeWellKnownGroup
	SidTypeDeletedAccount
	SidTypeInvalid
	SidTypeUnknown
	SidTypeComputer
	SidTypeLabel
)

var (
	procCreateWellKnownSid = advapi32.MustFindProc("CreateWellKnownSid")
	procLookupAccountSidW  = advapi32.MustFindProc("LookupAccountSidW")
)

// Storage for a SID. Although a SID is an opaque data structure, some API
// functions require an allocated buffer to be provided and therefore a native
// type needs to exist to manage access to the buffer. The Pointer() method can
// be used to convert it to a *windows.SID.
type SID struct {
	b [SECURITY_MAX_SID_SIZE]byte
}

// Create a SID from a well-known SID type. The sidDomain parameter identifies
// the domain to use and may be nil for the local computer.
func CreateWellKnownSid(sidType int32, sidDomain *SID) (*SID, error) {
	var sid SID
	ret, _, err := procCreateWellKnownSid.Call(
		uintptr(sidType),
		uintptr(unsafe.Pointer(sidDomain)),
		uintptr(unsafe.Pointer(&sid)),
		uintptr(unsafe.Pointer(unsafe.Sizeof(sid))),
	)
	if ret == 0 {
		return nil, err
	}
	return &sid, nil
}

// Obtain a pointer to the SID.
func (s *SID) Pointer() *windows.SID {
	return (*windows.SID)(unsafe.Pointer(s))
}

// Lookup the name and domain for the SID. The systemName parameter specifies
// the target computer and is optional. The returned values are the name,
// domain, and type of the SID. The underlying API function is invoked twice -
// once to obtain the required buffer sizes and the second time with the
// correctly sized buffers.
func (s *SID) Lookup(systemName string) (string, string, int32, error) {
	var (
		nameLen   uint32
		domainLen uint32
		use       int32
	)
	ret, _, err := procLookupAccountSidW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(systemName))),
		uintptr(unsafe.Pointer(s)),
		uintptr(0),
		uintptr(unsafe.Pointer(&nameLen)),
		uintptr(0),
		uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&use)),
	)
	var (
		name   = make([]uint16, nameLen)
		domain = make([]uint16, domainLen)
	)
	ret, _, err = procLookupAccountSidW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(systemName))),
		uintptr(unsafe.Pointer(s)),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&use)),
	)
	if ret == 0 {
		return "", "", 0, err
	}
	return windows.UTF16ToString(name), windows.UTF16ToString(domain), use, err
}
