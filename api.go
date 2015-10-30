package acl

import (
	"golang.org/x/sys/windows"

	"unsafe"
)

const (
	ERROR_SUCCESS = 0
)

const (
	SECURITY_MAX_SID_SIZE = 68
)

// SE_OBJECT_TYPE enumeration.
const (
	SE_UNKNOWN_OBJECT_TYPE = iota
	SE_FILE_OBJECT
	SE_SERVICE
	SE_PRINTER
	SE_REGISTRY_KEY
	SE_LMSHARE
	SE_KERNEL_OBJECT
	SE_WINDOW_OBJECT
	SE_DS_OBJECT
	SE_DS_OBJECT_ALL
	SE_PROVIDER_DEFINED_OBJECT
	SE_WMIGUID_OBJECT
	SE_REGISTRY_WOW64_32KEY
)

// SECURITY_INFORMATION flags.
const (
	OWNER_SECURITY_INFORMATION               = 0x00001
	GROUP_SECURITY_INFORMATION               = 0x00002
	DACL_SECURITY_INFORMATION                = 0x00004
	SACL_SECURITY_INFORMATION                = 0x00008
	LABEL_SECURITY_INFORMATION               = 0x00010
	ATTRIBUTE_SECURITY_INFORMATION           = 0x00020
	SCOPE_SECURITY_INFORMATION               = 0x00040
	PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00080
	BACKUP_SECURITY_INFORMATION              = 0x10000

	PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
	PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
	UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
	UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
)

// MULTIPLE_TRUSTEE_OPERATION enumeration.
const (
	NO_MULTIPLE_TRUSTEE = iota
	TRUSTEE_IS_IMPERSONATE
)

// TRUSTEE_FORM enumeration.
const (
	TRUSTEE_IS_SID = iota
	TRUSTEE_IS_NAME
	TRUSTEE_BAD_FORM
	TRUSTEE_IS_OBJECTS_AND_SID
	TRUSTEE_IS_OBJECTS_AND_NAME
)

// TRUSTEE_TYPE enumeration.
const (
	TRUSTEE_IS_UNKNOWN = iota
	TRUSTEE_IS_USER
	TRUSTEE_IS_GROUP
	TRUSTEE_IS_DOMAIN
	TRUSTEE_IS_ALIAS
	TRUSTEE_IS_WELL_KNOWN_GROUP
	TRUSTEE_IS_DELETED
	TRUSTEE_IS_INVALID
	TRUSTEE_IS_COMPUTER
)

// ACCESS_MODE enumeration.
const (
	NOT_USED_ACCESS = iota
	GRANT_ACCESS
	SET_ACCESS
	DENY_ACCESS
	REVOKE_ACCESS
	SET_AUDIT_SUCCESS
	SET_AUDIT_FAILURE
)

// ACE flags.
const (
	NO_INHERITANCE                     = 0x0
	SUB_OBJECTS_ONLY_INHERIT           = 0x1
	SUB_CONTAINERS_ONLY_INHERIT        = 0x2
	SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3
	INHERIT_NO_PROPAGATE               = 0x4
	INHERIT_ONLY                       = 0x8

	OBJECT_INHERIT_ACE       = 0x1
	CONTAINER_INHERIT_ACE    = 0x2
	NO_PROPAGATE_INHERIT_ACE = 0x4
	INHERIT_ONLY_ACE         = 0x8
)

// WELL_KNOWN_SID_TYPE enumeration.
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

var (
	advapi32 = windows.MustLoadDLL("advapi32.dll")

	procGetNamedSecurityInfoW = advapi32.MustFindProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfoW = advapi32.MustFindProc("SetNamedSecurityInfoW")
	procCreateWellKnownSid    = advapi32.MustFindProc("CreateWellKnownSid")
	procSetEntriesInAclW      = advapi32.MustFindProc("SetEntriesInAclW")
)

type ACL struct{}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379636.aspx
type Trustee struct {
	MultipleTrustee          *Trustee
	MultipleTrusteeOperation int32
	TrusteeForm              int32
	TrusteeType              int32
	Name                     *uint16
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446627.aspx
type ExplicitAccess struct {
	AccessPermissions uint32
	AccessMode        int32
	Inheritance       uint32
	Trustee           Trustee
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446645.aspx
func GetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner, group **windows.SID, dacl, sacl **ACL, secDesc *windows.Handle) error {
	ret, _, err := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(objectName))),
		uintptr(objectType),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(owner)),
		uintptr(unsafe.Pointer(group)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
		uintptr(unsafe.Pointer(secDesc)),
	)
	if ret != ERROR_SUCCESS {
		return err
	}
	return nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379579.aspx
func SetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner, group *windows.SID, dacl, sacl *ACL) error {
	ret, _, err := procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(objectName))),
		uintptr(objectType),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(owner)),
		uintptr(unsafe.Pointer(group)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
	)
	if ret != ERROR_SUCCESS {
		return err
	}
	return nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446585.aspx
func CreateWellKnownSid(sidType int32, sidDomain, sid *windows.SID, sidLen *uint32) error {
	ret, _, err := procCreateWellKnownSid.Call(
		uintptr(sidType),
		uintptr(unsafe.Pointer(sidDomain)),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(sidLen)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379576.aspx
func SetEntriesInAcl(entries []ExplicitAccess, oldAcl *ACL, newAcl **ACL) error {
	ret, _, err := procSetEntriesInAclW.Call(
		uintptr(len(entries)),
		uintptr(unsafe.Pointer(&entries[0])),
		uintptr(unsafe.Pointer(oldAcl)),
		uintptr(unsafe.Pointer(newAcl)),
	)
	if ret != ERROR_SUCCESS {
		return err
	}
	return nil
}
