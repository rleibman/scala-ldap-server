package ldap.rfc4533
import ldap._
import asn1._
import scala.concurrent.Future
import java.util.UUID
import dao.DAO

object RFC4533Plugin extends Plugin {
  val `e-syncRefreshRequired` = new LDAPResultType(4096)
  val LDAPContentSynchronization = ldap.SupportedControl(
    LDAPOID("1.3.6.1.4.1.4203.1.9.1.1"),
    "Sync Request Control")
  val LDAPSyncState = ldap.SupportedControl(LDAPOID("1.3.6.1.4.1.4203.1.9.1.2"),
                                            "Sync State Control")
  val LDAPContentSynchronizationDone = ldap.SupportedControl(
    LDAPOID("1.3.6.1.4.1.4203.1.9.1.3"),
    "Sync Done Control")

  override def resultTypes(): Seq[LDAPResultType] = Seq(`e-syncRefreshRequired`)
  override def supportedControls(): Seq[ldap.SupportedControl] =
    Seq(LDAPContentSynchronization,
        LDAPSyncState,
        LDAPContentSynchronizationDone)

  override def initialize(config: com.typesafe.config.Config): Future[Unit] = {
    Future.successful {
      if (config.hasPath("scala-ldap-server.syncrepl")) {
        val syncrepl = config.getConfig("scala-ldap-server.syncrepl")
        val replicaId = syncrepl.getString("rid")
        val providerUri = syncrepl.getString("providerUri")
        val syncType = syncrepl.getString("syncType") //refreshOnly or RefreshAndPersist
        val interval = syncrepl.getString("interval")
        val searchbase = syncrepl.getString("searchbase")
        val filter = syncrepl.getString("filter")
        val scope = syncrepl.getString("scope") //sub|one|base
        val attrs = syncrepl.getStringList("attrs")
        val attrsOnly = syncrepl.getString("attrsOnly")
        val sizeLimit = syncrepl.getString("sizeLimit")
        val timeLimit = syncrepl.getString("timeLimit")
        val schemaChecking = syncrepl.getString("schemaiChecking") //on|off
        val bindMethod = syncrepl.getString("bindMethod") //simple|sasl
        val binddn = syncrepl.getString("binddn")
        val saslmech = syncrepl.getString("saslmech")
        val authcid = syncrepl.getString("authcid")
        val authzid = syncrepl.getString("authzid")
        val credentials = syncrepl.getString("credentials")
        val realm = syncrepl.getString("realm")
        val secprops = syncrepl.getStringList("secprops")
        val startttls = syncrepl.getString("startttls") //yes|critical
        val tls_cert = syncrepl.getString("tls_cert")
        val tls_key = syncrepl.getString("tls_key")
        val tls_cacert = syncrepl.getString("tls_cacert")
        val tls_cacertdir = syncrepl.getString("tls_cacertdir")
        val tls_reqcert = syncrepl.getString("tls_reqcert") //never|allow|try|demand
        val tls_ciphersuite = syncrepl.getStringList("tls_ciphersuite")
        val tls_crlcheck = syncrepl.getString("tls_crlchcek") //none|peer|all
        val logbase = syncrepl.getString("logbase")
        val logfilter = syncrepl.getString("logfilter")
        val syncdata = syncrepl.getString("syncdata") //default|accesslog|changelog

      }
      //        syncrepl rid=<replica ID>
      //                provider=ldap[s]://<hostname>[:port]
      //                [type=refreshOnly|refreshAndPersist]
      //                [interval=dd:hh:mm:ss]
      //                [retry=[<retry interval> <# of retries>]+]
      //                searchbase=<base DN>
      //                [filter=<filter str>]
      //                [scope=sub|one|base]
      //                [attrs=<attr list>]
      //                [attrsonly]
      //                [sizelimit=<limit>]
      //                [timelimit=<limit>]
      //                [schemachecking=on|off]
      //                [bindmethod=simple|sasl]
      //                [binddn=<DN>]
      //                [saslmech=<mech>]
      //                [authcid=<identity>]
      //                [authzid=<identity>]
      //                [credentials=<passwd>]
      //                [realm=<realm>]
      //                [secprops=<properties>]
      //                [starttls=yes|critical]
      //                [tls_cert=<file>]
      //                [tls_key=<file>]
      //                [tls_cacert=<file>]
      //                [tls_cacertdir=<path>]
      //                [tls_reqcert=never|allow|try|demand]
      //                [tls_ciphersuite=<ciphers>]
      //                [tls_crlcheck=none|peer|all]
      //                [logbase=<base DN>]
      //                [logfilter=<filter str>]
      //                [syncdata=default|accesslog|changelog]

      // TODO Figure out if there's a server that we need to sync with, and sync with it

    }
  }

  override def decodeApplication(
      applicationAsn1: Asn1Application): Option[MessageProtocolOp] = {
    import SyncInfoMessage._
    applicationAsn1.tag match {
      case 25 ⇒ //IntermediateResponse
        applicationAsn1.value.toSeq match {
          case Seq(Asn1String(SyncInfoMessage.oid.value),
                   details: Asn1Sequence) ⇒
            details.value.toSeq match {
              case Seq(Asn1Number(0), Asn1String(cookieStr)) =>
                Some(SyncInfoMessage(Cookie(SyncCookie(cookieStr))))
              case Asn1Number(1) :: tail =>
                val cookie = tail.collectFirst {
                  case Asn1String(str) => SyncCookie(str)
                }
                val refreshDone = tail
                  .collectFirst { case Asn1Boolean(value) => value }
                  .getOrElse(false)
                Some(SyncInfoMessage(RefreshDelete(cookie, refreshDone)))
              case Asn1Number(2) :: tail =>
                val cookie = tail.collectFirst {
                  case Asn1String(str) => SyncCookie(str)
                }
                val refreshDone = tail
                  .collectFirst { case Asn1Boolean(value) => value }
                  .getOrElse(false)
                Some(SyncInfoMessage(RefreshPresent(cookie, refreshDone)))
              case Asn1Number(3) :: tail =>
                val cookie = tail.collectFirst {
                  case Asn1String(str) => SyncCookie(str)
                }
                val refreshDeletes = tail
                  .collectFirst { case Asn1Boolean(value) => value }
                  .getOrElse(false)
                val syncUUIDs = tail
                  .collect {
                    case Asn1Set(set) =>
                      set.collect {
                        case Asn1String(str) => UUID.fromString(str)
                      }
                  }
                  .toSet
                  .flatten
                Some(
                  SyncInfoMessage(SyncIdSet(cookie, refreshDeletes, syncUUIDs)))
              case _ =>
                throw new Error(s"Unknown Sync Info Message: ${details}")
            }
          case _ => None //Don't know this dude
        }
      case _ => None //Don't know this dude
    }
  }
  override def decodeControl(controlAsn1: Asn1Object): Option[Control] = {
    controlAsn1 match {
      case Seq(Asn1String(LDAPContentSynchronization.oid.value),
               Asn1Boolean(criticality),
               details: Asn1Sequence) =>
        val seq = details.value.toSeq
        val mode = seq.collectFirst {
          case Asn1Enumerated(mode) => SyncRequestControlMode.fromMode(mode)
        }.get
        val cookie = seq.collectFirst {
          case Asn1String(str) => SyncCookie(str)
        }
        val reloadHint =
          seq.collectFirst { case Asn1Boolean(value) => value }.getOrElse(false)
        Some(SyncRequestControl(criticality, mode, cookie, reloadHint))
      case Seq(Asn1String(LDAPSyncState.oid.value), details: Asn1Sequence) =>
        val seq = details.value.toSeq
        val state = seq.collectFirst {
          case Asn1Enumerated(state) => SyncStateType.fromState(state)
        }.get
        val syncUUID = seq.collectFirst { case Asn1String(str) => str }.get
        val cookie = seq.reverse.collectFirst {
          case Asn1String(str) if (str != syncUUID) => SyncCookie(str)
        }
        Some(SyncStateControl(state, UUID.fromString(syncUUID), cookie))
      case Seq(Asn1String(LDAPContentSynchronizationDone.oid.value),
               details: Asn1Sequence) =>
        val seq = details.value.toSeq
        val cookie = seq.collectFirst {
          case Asn1String(str) => SyncCookie(str)
        }
        val refreshDeletes =
          seq.collectFirst { case Asn1Boolean(value) => value }.getOrElse(false)
        Some(SyncDoneControl(cookie, refreshDeletes))
      case _ => None //Don't know this dude
    }
  }

  override def operate(msg: LdapMessage,
                       preResults: Seq[LdapMessage],
                       dao: DAO): Future[Seq[LdapMessage]] = Future.successful {
    val newCookie = Some(SyncCookie())
    if (msg.controls.exists(_.controlType == LDAPContentSynchronization)) {
      val res = preResults.map(result => {
        result.protocolOp match {
          case SearchResultEntry(id, nodeDN, filter) =>
            val syncStateControl =
              SyncStateControl(SyncStateType.add, id, newCookie)
            result.copy(controls = result.controls :+ syncStateControl)
          case SearchResultDone(ldapResult) =>
            val syncDoneControl = SyncDoneControl(newCookie)
            result.copy(controls = result.controls :+ syncDoneControl)
          case _ => result
        }
      })
      res
    } else if (msg.controls.exists(_.controlType == LDAPSyncState)) {
      //TODO: this is a message from another LDAP server, telling us that a change has happened and that we need to do something about it
      ???
    } else {
      //Do nothing, this plugin doesn't have any skin in the game
      preResults
    }
  }
}
