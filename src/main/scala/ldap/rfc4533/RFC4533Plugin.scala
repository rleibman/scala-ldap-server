package ldap.rfc4533
import ldap._
import asn1._
import scala.concurrent.Future

object RFC4533Plugin extends Plugin {
  val `e-syncRefreshRequired` = new LDAPResultType(4096)
  val LDAPContentSynchronization = ldap.SupportedControl(LDAPOID("1.3.6.1.4.1.4203.1.9.1.1"), "Sync Request Control")
  val LDAPSyncState = ldap.SupportedControl(LDAPOID("1.3.6.1.4.1.4203.1.9.1.2"), "Sync State Control")
  val LDAPContentSynchronizationDone = ldap.SupportedControl(LDAPOID("1.3.6.1.4.1.4203.1.9.1.3"), "Sync Done Control")

  override def resultTypes(): Seq[LDAPResultType] = Seq(`e-syncRefreshRequired`)
  override def supportedControls(): Seq[ldap.SupportedControl] = Seq(LDAPContentSynchronization, LDAPSyncState, LDAPContentSynchronizationDone)

  override def decodeApplication(applicationAsn1: Asn1Application): Option[MessageProtocolOp] = {
    applicationAsn1.tag match {
      case 25 ⇒ //IntermediateResponse
        applicationAsn1.value.toSeq match {
          case Seq(Asn1String(SyncInfoMessage.oid.value), details: Asn1Object) ⇒
            println(details)
            Some(SyncInfoMessage(null)) //TODO figure out what kind of SyncInfoMessage it is based on the details
          case _ => None //Don't know this dude
        }
      case _ => None //Don't know this dude
    }
  }
  override def decodeControl(controlAsn1: Asn1Object): Option[Control] = {
    controlAsn1 match {
      case Seq(Asn1String(LDAPContentSynchronization.oid.value), Asn1Boolean(criticality), details: Asn1Object) =>
        Some(SyncRequestControl(criticality, null, null, false)) //TODO details
      case Seq(Asn1String(LDAPSyncState.oid.value), details: Asn1Object) =>
        Some(SyncStateControl(null, null, null)) //TODO details
      case Seq(Asn1String(LDAPContentSynchronizationDone.oid.value), details: Asn1Object) =>
        Some(SyncDoneControl(null, false)) //TODO details
      case _ => None //Don't know this dude
    }
  }

  override def operate(msg: LdapMessage, preResults: Seq[LdapMessage]): Seq[LdapMessage] = {
    val newCookie = Some(SyncCookie())
    if (msg.controls.exists(_.controlType == LDAPContentSynchronization)) {
      val res = preResults.map(result => {
        result.protocolOp match {
          case SearchResultEntry(id, nodeDN, filter) =>
            val syncStateControl = SyncStateControl(SyncStateType.add, id, newCookie)
            result.copy(controls = result.controls :+ syncStateControl)
          case SearchResultDone(ldapResult) =>
            val syncDoneControl = SyncDoneControl(newCookie)
            result.copy(controls = result.controls :+ syncDoneControl)
          case _ => result
        }
      })
    }
    if (msg.controls.exists(_.controlType == LDAPSyncState)) {
      //TODO: this is a message from another LDAP server, telling us that a change has happened and that we need to do something about it
    } else {
      //Do nothing, this plugin doesn't have any skin in the game
      preResults
    }

    ???
  }
}