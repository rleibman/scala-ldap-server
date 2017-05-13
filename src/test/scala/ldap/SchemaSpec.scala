package ldap

import org.scalatest.FlatSpec

class SchemaSpec extends FlatSpec with Config {
  "parsing some ldap syntaxes" should "parse them" in {
    val specs = List(
      " ( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' X-NOT-HUMAN-READABLE  'TRUE' ) ",
      " ( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' X-NOT-HUMAN-READABLE 'TRUE' ) ",
      " ( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' ) ",
      " ( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' ) ",
      " ( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' ) ",
      " ( 1.3.6.1.4.1.1466.115.121.1.9 DESC 'Certificate List' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' ) "
    )
    specs.foreach { spec =>
      val syntax = LdapSyntax(spec)
      assert(syntax.isDefined)
      println(syntax)
    }
  }
  "parsing some matchingRules" should "parse them" in {
    val specs = List(
      " ( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 ) ",
      " ( 1.3.6.1.1.16.2 NAME 'UUIDMatch' SYNTAX 1.3.6.1.1.16.1 ) ",
      " ( 1.2.840.113556.1.4.804 NAME 'integerBitOrMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 ) ",
      " ( 1.2.840.113556.1.4.803 NAME 'integerBitAndMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 ) "
    )
    specs.foreach { spec =>
      val syntax = MatchingRule(spec)
      assert(syntax.isDefined)
      println(syntax)
    }
  }
  "parsing some matchingRuleUses" should "parse them" in {
    val specs = List(
      " ( 2.5.13.23 NAME 'uniqueMemberMatch' APPLIES uniqueMember ) ",
      " ( 2.5.13.22 NAME 'presentationAddressMatch' APPLIES presentationAddress ) ",
      " ( 2.5.13.20 NAME 'telephoneNumberMatch' APPLIES ( telephoneNumber $ homePhone $ mobile $ pager ) ) ",
      " ( 2.5.13.18 NAME 'octetStringOrderingMatch' APPLIES ( userPassword $ olcDbCryptKey $ sambaClearTextPassword $ sambaPreviousClearTextPassword $ sshPublicKey ) ) ",
      " ( 2.5.13.17 NAME 'octetStringMatch' APPLIES ( userPassword $ olcDbCryptKey $ sambaClearTextPassword $ sambaPreviousClearTextPassword $ sshPublicKey ) ) ",
      " ( 2.5.13.16 NAME 'bitStringMatch' APPLIES x500UniqueIdentifier ) ",
      " ( 2.5.13.15 NAME 'integerOrderingMatch' APPLIES ( supportedLDAPVersion $ entryTtl $ uidNumber $ gidNumber $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcIdleTimeout $ olcIndexSubstrIfMinLen $ olcIndexSubstrIfMaxLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcMaxDerefDepth $ olcReplicationInterval $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcThreads $ olcToolThreads $ olcWriteTimeout $ olcDbCacheFree $ olcDbCacheSize $ olcDbDNcacheSize $ olcDbIDLcacheSize $ olcDbSearchStack $ olcDbShmKey $ mailPreferenceOption $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ ipServicePort $ ipProtocolNumber $ oncRpcNumber $ sambaPwdLastSet $ sambaPwdCanChange $ sambaPwdMustChange $ sambaLogonTime $ sambaLogoffTime $ sambaKickoffTime $ sambaBadPasswordCount $ sambaBadPasswordTime $ sambaGroupType $ sambaNextUserRid $ sambaNextGroupRid $ sambaNextRid $ sambaAlgorithmicRidBase $ sambaIntegerOption $ sambaMinPwdLength $ sambaPwdHistoryLength $ sambaLogonToChgPwd $ sambaMaxPwdAge $ sambaMinPwdAge $ sambaLockoutDuration $ sambaLockoutObservationWindow $ sambaLockoutThreshold $ sambaForceLogoff $ sambaRefuseMachinePwdChange $ fdMinId $ fdUidNumberBase $ fdGidNumberBase $ fdGidNumberPoolMin $ fdUidNumberPoolMin $ fdGidNumberPoolMax $ fdUidNumberPoolMax $ fdPasswordMinLength $ fdPasswordMinDiffer $ fdLdapSizeLimit $ fdSessionLifeTime $ fdLdapMaxQueryTime $ fdDebugLevel $ passwordRecoveryValidity $ goLdapSizeLimit $ goLdapTimeLimit $ saRequiredScore $ avMaxThreads $ avMaxDirectoryRecursions $ avArchiveMaxFileSize $ avArchiveMaxRecursion $ avArchiveMaxCompressionRatio $ avChecksPerDay $ sudoOrder $ fdImapTimeout $ pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval ) ) ",
      " ( 2.5.13.14 NAME 'integerMatch' APPLIES ( supportedLDAPVersion $ entryTtl $ uidNumber $ gidNumber $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcIdleTimeout $ olcIndexSubstrIfMinLen $ olcIndexSubstrIfMaxLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcMaxDerefDepth $ olcReplicationInterval $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcThreads $ olcToolThreads $ olcWriteTimeout $ olcDbCacheFree $ olcDbCacheSize $ olcDbDNcacheSize $ olcDbIDLcacheSize $ olcDbSearchStack $ olcDbShmKey $ mailPreferenceOption $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ ipServicePort $ ipProtocolNumber $ oncRpcNumber $ sambaPwdLastSet $ sambaPwdCanChange $ sambaPwdMustChange $ sambaLogonTime $ sambaLogoffTime $ sambaKickoffTime $ sambaBadPasswordCount $ sambaBadPasswordTime $ sambaGroupType $ sambaNextUserRid $ sambaNextGroupRid $ sambaNextRid $ sambaAlgorithmicRidBase $ sambaIntegerOption $ sambaMinPwdLength $ sambaPwdHistoryLength $ sambaLogonToChgPwd $ sambaMaxPwdAge $ sambaMinPwdAge $ sambaLockoutDuration $ sambaLockoutObservationWindow $ sambaLockoutThreshold $ sambaForceLogoff $ sambaRefuseMachinePwdChange $ fdMinId $ fdUidNumberBase $ fdGidNumberBase $ fdGidNumberPoolMin $ fdUidNumberPoolMin $ fdGidNumberPoolMax $ fdUidNumberPoolMax $ fdPasswordMinLength $ fdPasswordMinDiffer $ fdLdapSizeLimit $ fdSessionLifeTime $ fdLdapMaxQueryTime $ fdDebugLevel $ passwordRecoveryValidity $ goLdapSizeLimit $ goLdapTimeLimit $ saRequiredScore $ avMaxThreads $ avMaxDirectoryRecursions $ avArchiveMaxFileSize $ avArchiveMaxRecursion $ avArchiveMaxCompressionRatio $ avChecksPerDay $ sudoOrder $ fdImapTimeout $ pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval ) ) ",
      " ( 2.5.13.13 NAME 'booleanMatch' APPLIES ( hasSubordinates $ olcAddContentAcl $ olcGentleHUP $ olcHidden $ olcLastMod $ olcMirrorMode $ olcMonitoring $ olcReadOnly $ olcReverseLookup $ olcSyncUseSubentry $ olcDbChecksum $ olcDbNoSync $ olcDbDirtyRead $ olcDbLinearIndex $ sambaBoolOption $ fdRfc2307bis $ fdSchemaCheck $ fdPersonalTitleInDN $ fdStrictNamingRules $ fdHandleExpiredAccounts $ fdForcePasswordDefaultHash $ fdPrimaryGroupFilter $ fdListSummary $ fdHonourUnitTags $ fdCopyPaste $ fdLogging $ fdForceSSL $ fdWarnSSL $ fdStoreFilterSettings $ fdDisplayErrors $ fdLdapStats $ fdEnableSnapshots $ fdHonourIvbbAttributes $ fdDisplayHookOutput $ fdAclTabOnObjects $ passwordRecoveryActivated $ passwordRecoveryUseAlternate $ fdCyrusUseSlashes $ fdCyrusDeleteMailbox $ pwdLockout $ pwdMustChange $ pwdAllowUserChange $ pwdSafeModify ) ) ",
      " ( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES ( postalAddress $ registeredAddress $ homePostalAddress ) ) ",
      " ( 2.5.13.9 NAME 'numericStringOrderingMatch' APPLIES ( x121Address $ internationaliSDNNumber $ fdMobileIMEI $ fdMobilePUK ) ) ",
      " ( 2.5.13.8 NAME 'numericStringMatch' APPLIES ( x121Address $ internationaliSDNNumber $ fdMobileIMEI $ fdMobilePUK ) ) ",
      " ( 2.5.13.7 NAME 'caseExactSubstringsMatch' APPLIES ( serialNumber $ destinationIndicator $ dnQualifier ) ) ",
      " ( 2.5.13.6 NAME 'caseExactOrderingMatch' APPLIES ( supportedSASLMechanisms $ vendorName $ vendorVersion $ ref $ name $ cn $ uid $ labeledURI $ description $ olcConfigFile $ olcConfigDir $ olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAttributeTypes $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcBackend $ olcDatabase $ olcDisallows $ olcDitContentRules $ olcExtraAttrs $ olcInclude $ olcLdapSyntaxes $ olcLimits $ olcLogFile $ olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectClasses $ olcObjectIdentifier $ olcOverlay $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPlugin $ olcPluginLogFile $ olcReferral $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDSE $ olcRootPW $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSortVals $ olcSubordinate $ olcSyncrepl $ olcTCPBuffer $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSCRLFile $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSProtocolMin $ olcUpdateRef $ olcDbDirectory $ olcDbCheckpoint $ olcDbCryptFile $ olcDbPageSize $ olcDbIndex $ olcDbLockDetect $ olcDbMode $ knowledgeInformation $ sn $ serialNumber $ c $ l $ st $ street $ o $ ou $ title $ businessCategory $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ destinationIndicator $ givenName $ initials $ generationQualifier $ dnQualifier $ houseIdentifier $ dmdName $ pseudonym $ textEncodedORAddress $ info $ drink $ roomNumber $ userClass $ host $ documentIdentifier $ documentTitle $ documentVersion $ documentLocation $ personalTitle $ co $ uniqueIdentifier $ organizationalStatus $ buildingName $ documentPublisher $ ipServiceProtocol $ nisMapName $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ preferredLanguage $ sambaLogonScript $ sambaProfilePath $ sambaUserWorkstations $ sambaHomePath $ sambaDomainName $ sambaMungedDial $ sambaShareName $ sambaOptionName $ sambaStringListOption $ gosaSubtreeACL $ gosaUser $ gosaObject $ gosaSnapshotType $ gosaSnapshotTimestamp $ gosaSnapshotDN $ gosaLoginRestriction $ academicTitle $ datefBirth $ authorizedService $ passwordRecoveryMailSubject $ passwordRecoveryMailBody $ passwordRecoveryMail2Subject $ passwordRecoveryMail2Body $ goExportEntry $ goLdapBase $ goLdapURI $ goLdapDeref $ goLdapTlsCert $ goLdapTlsKey $ goLdapTlsCaCert $ goLdapReqCert $ goLdapCrlCheck $ gotoLogonScript $ gotoLogoffScript $ gotoLdapServer $ gosaVacationMessage $ gosaVacationStart $ gosaVacationStop $ fdApplicationTitle $ fdApplicationImageLocation $ fdApplicationVariables $ fdApplicationExecutePath $ fdApplicationAllowed $ apacheServerName $ apacheServerAlias $ apacheDocumentRoot $ apacheServerAdmin $ apacheScriptAlias $ apacheSuexecUid $ apacheSuexecGid ) ) ",
      " ( 2.5.13.5 NAME 'caseExactMatch' APPLIES ( supportedSASLMechanisms $ vendorName $ vendorVersion $ ref $ name $ cn $ uid $ labeledURI $ description $ olcConfigFile $ olcConfigDir $ olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAttributeTypes $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcBackend $ olcDatabase $ olcDisallows $ olcDitContentRules $ olcExtraAttrs $ olcInclude $ olcLdapSyntaxes $ olcLimits $ olcLogFile $ olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectClasses $ olcObjectIdentifier $ olcOverlay $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPlugin $ olcPluginLogFile $ olcReferral $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDSE $ olcRootPW $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSortVals $ olcSubordinate $ olcSyncrepl $ olcTCPBuffer $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSCRLFile $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSProtocolMin $ olcUpdateRef $ olcDbDirectory $ olcDbCheckpoint $ olcDbCryptFile $ olcDbPageSize $ olcDbIndex $ olcDbLockDetect $ olcDbMode $ knowledgeInformation $ sn $ serialNumber $ c $ l $ st $ street $ o $ ou $ title $ businessCategory $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ destinationIndicator $ givenName $ initials $ generationQualifier $ dnQualifier $ houseIdentifier $ dmdName $ pseudonym $ textEncodedORAddress $ info $ drink $ roomNumber $ userClass $ host $ documentIdentifier $ documentTitle $ documentVersion $ documentLocation $ personalTitle $ co $ uniqueIdentifier $ organizationalStatus $ buildingName $ documentPublisher $ ipServiceProtocol $ nisMapName $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ preferredLanguage $ sambaLogonScript $ sambaProfilePath $ sambaUserWorkstations $ sambaHomePath $ sambaDomainName $ sambaMungedDial $ sambaShareName $ sambaOptionName $ sambaStringListOption $ gosaSubtreeACL $ gosaUser $ gosaObject $ gosaSnapshotType $ gosaSnapshotTimestamp $ gosaSnapshotDN $ gosaLoginRestriction $ academicTitle $ dateOfBirth $ authorizedService $ passwordRecoveryMailSubject $ passwordRecoveryMailBody $ passwordRecoveryMail2Subject $ passwordRecoveryMail2Body $ goExportEntry $ goLdapBase $ goLdapURI $ goLdapDeref $ goLdapTlsCert $ goLdapTlsKey $ goLdapTlsCaCert $ goLdapReqCert $ goLdapCrlCheck $ gotoLogonScript $ gotoLogoffScript $ gotoLdapServer $ gosaVacationMessage $ gosaVacationStart $ gosaVacationStop $ fdApplicationTitle $ fdApplicationImageLocation $ fdApplicationVariables $ fdApplicationExecutePath $ fdApplicationAllowed $ apacheServerName $ apacheServerAlias $ apacheDocumentRoot $ apacheServerAdmin $ apacheScriptAlias $ apacheSuexecUid $ apacheSuexecGid ) ) ",
      " ( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' APPLIES ( serialNumber $ destinationIndicator $ dnQualifier ) ) ",
      " ( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' APPLIES ( supportedSASLMechanisms $ vendorName $ vendorVersion $ ref $ name $ cn $ uid $ labeledURI $ description $ olcConfigFile $ olcConfigDir $ olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAttributeTypes $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcBackend $ olcDatabase $ olcDisallows $ olcDitContentRules $ olcExtraAttrs $ olcInclude $ olcLdapSyntaxes $ olcLimits $ olcLogFile $ olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectClasses $ olcObjectIdentifier $ olcOverlay $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPlugin $ olcPluginLogFile $ olcReferral $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDSE $ olcRootPW $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSortVals $ olcSubordinate $ olcSyncrepl $ olcTCPBuffer $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSCRLFile $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSProtocolMin $ olcUpdateRef $ olcDbDirectory $ olcDbCheckpoint $ olcDbCryptFile $ olcDbPageSize $ olcDbIndex $ olcDbLockDetect $ olcDbMode $ knowledgeInformation $ sn $ serialNumber $ c $ l $ st $ street $ o $ ou $ title $ businessCategory $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ destinationIndicator $ givenName $ initials $ generationQualifier $ dnQualifier $ houseIdentifier $ dmdName $ pseudonym $ textEncodedORAddress $ info $ drink $ roomNumber $ userClass $ host $ documentIdentifier $ documentTitle $ documentVersion $ documentLocation $ personalTitle $ co $ uniqueIdentifier $ organizationalStatus $ buildingName $ documentPublisher $ ipServiceProtocol $ nisMapName $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ preferredLanguage $ sambaLogonScript $ sambaProfilePath $ sambaUserWorkstations $ sambaHomePath $ sambaDomainName $ sambaMungedDial $ sambaShareName $ sambaOptionName $ sambaStringListOption $ gosaSubtreeACL $ gosaUser $ gosaObject $ gosaSnapshotType $ gosaSnapshotTimestamp $ gosaSnapshotDN $ gosaLoginRestriction $ academicTitle $ dateOfBirth $ authorizedService $ passwordRecoveryMailSubject $ passwordRecoveryMailBody $ passwordRecoveryMail2Subject $ passwordRecoveryMail2Body $ goExportEntry $ goLdapBase $ goLdapURI $ goLdapDeref $ goLdapTlsCert $ goLdapTlsKey $ goLdapTlsCaCert $ goLdapReqCert $ goLdapCrlCheck $ gotoLogonScript $ gotoLogoffScript $ gotoLdapServer $ gosaVacationMessage $ gosaVacationStart $ gosaVacationStop $ fdApplicationTitle $ fdApplicationImageLocation $ fdApplicationVariables $ fdApplicationExecutePath $ fdApplicationAllowed $ apacheServerName $ apacheServerAlias $ apacheDocumentRoot $ apacheServerAdmin $ apacheScriptAlias $ apacheSuexecUid $ apacheSuexecGid ) ) "
    )
    specs.foreach { spec =>
      val syntax = MatchingRuleUse(spec)
      assert(syntax.isDefined)
      println(syntax)
    }
  }
  "parsing some attributeTypes" should "parse them" in {
    val specs = List(
      " ( 2.5.4.0 NAME 'objectClass' DESC 'RFC4512: object classes of the entity' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 ) ",
      " ( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name for which the entity is known by' SUP name ) ",
      " ( 1.3.6.1.4.1.10098.1.1.12.33 NAME 'gosaUnitTag' DESC 'Takes a list of relevant mime-type|priority settings' OBSOLETE EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE ) ",
      " ( 2.5.4.4 NAME ( 'sn' 'surname' ) DESC 'RFC2256: last family name(s) for which the entity is known by' SUP name ) ",
      " ( 2.5.21.9 NAME ( 'structuralObjectClass' 'somethingelse' ) DESC 'RFC4512: structural object class of entry' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation ) "
    )
    specs.foreach { spec =>
      val syntax = AttributeType(spec)
      assert(syntax.isDefined)
      println(syntax)
    }
  }

  "parsing some objectClasses" should "parse them" in {
    val specs = List(
      " ( 1.3.6.1.4.1.4203.1.12.2.4.0.4 NAME 'olcDatabaseConfig' DESC 'OpenLDAP Database-specific options' OBSOLETE SUP olcConfig STRUCTURAL MUST ( olcDatabase $ fake ) MAY ( olcHidden $ olcSuffix $ olcSubordinate $ olcAccess $ olcAddContentAcl $ olcLastMod $ olcLimits $ olcMaxDerefDepth $ olcPlugin $ olcReadOnly $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplicationInterval $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDN $ olcRootPW $ olcSchemaDN $ olcSecurity $ olcSizeLimit $ olcSyncUseSubentry $ olcSyncrepl $ olcTimeLimit $ olcUpdateDN $ olcUpdateRef $ olcMirrorMode $ olcMonitoring $ olcExtraAttrs ) ) ",
      " ( 1.3.6.1.4.1.10098.1.2.1.19.15 NAME 'gosaAdministrativeUnit' DESC 'Marker for administrational units (v2.6.1)' OBSOLETE SUP top AUXILIARY MUST gosaUnitTag ) ",
      " ( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass ) ",
      " ( 2.5.20.1 NAME 'subschema' DESC 'RFC4512: controlling subschema (sub)entry' AUXILIARY MAY ( dITStructureRules $ nameForms $ dITContentRules $ objectClasses $ attributeTypes $ matchingRules $ matchingRuleUse ) ) ",
      " ( 0.9.2342.19200300.100.4.20 NAME 'pilotOrganization' SUP ( organization $ organizationalUnit ) STRUCTURAL MAY buildingName ) "
    )
    specs.foreach { spec =>
      val syntax = ObjectClass(spec)
      assert(syntax.isDefined)
      println(syntax)
    }
  }

  "Taking a look at the whole embedded schema" should "show the schema" in {
    println(BaseSchemaPlugin.ldapSyntaxes.size)
    println(BaseSchemaPlugin.attributeTypes.size)
    println(BaseSchemaPlugin.matchingRules.size)
    println(BaseSchemaPlugin.matchingRuleUses.size)
    println(BaseSchemaPlugin.objectClasses.size)
  }

  "look at the schema node" should "show the schemas" in {
    assert(SchemaNode.userAttributes("ldapSyntaxes").size > 20)
    assert(SchemaNode.userAttributes("matchingRules").size > 20)
    assert(SchemaNode.userAttributes("matchingRuleUse").size > 20)
    assert(SchemaNode.userAttributes("attributeTypes").size > 20)
    assert(SchemaNode.userAttributes("objectClasses").size > 20)
  }

}