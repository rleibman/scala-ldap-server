package ldap.rfc4533
import ldap._
import java.util.UUID

object SyncInfoMessage {
  val oid = LDAPOID("1.3.6.1.4.1.4203.1.9.1.4")
  sealed abstract trait SyncInfoValue
  case class Cookie(newCookie: String)
  case class RefreshDelete(newCookie: Option[String], refreshDone: Boolean = true)
  case class RefreshPresent(newCookie: Option[String], refreshDone: Boolean = true)
  case class RefreshIdSet(newCookie: Option[String], refreshDeletes: Boolean = true, syncUUIDs: Seq[UUID])
}

case class SyncInfoMessage(value: SyncInfoMessage.SyncInfoValue) extends IntermediateRespose {
  override val oid = Some(SyncInfoMessage.oid)
}

object SyncRequestControlMode extends Enumeration {
  type SyncRequestControlMode = Value
  val refreshOnly, refreshAndPersist = Value
}

import SyncRequestControlMode._

object SyncCookie {
  def apply(): SyncCookie = SyncCookie(System.currentTimeMillis().toString)
}
case class SyncCookie(value: String) {
  def time = value.toLong
}

case class SyncRequestControl(override val criticality: Boolean = false, modes: SyncRequestControlMode = refreshOnly, cookie: Option[SyncCookie] = None, reloadHint: Boolean = false) extends Control {
  override val controlType = RFC4533Plugin.LDAPContentSynchronization
}

object SyncStateType extends Enumeration {
  type SyncStateType = Value
  val present, add, modify, delete = Value
}

import SyncStateType._

case class SyncStateControl(syncStateValue: SyncStateType, uuid: UUID, cookie: Option[SyncCookie] = None) extends Control {
  override val criticality: Boolean = false
  override val controlType = RFC4533Plugin.LDAPContentSynchronization
}

case class SyncDoneControl(cookie: Option[SyncCookie] = None, refreshDeletes: Boolean = false) extends Control {
  override val criticality: Boolean = false
  override val controlType = RFC4533Plugin.LDAPContentSynchronization
}

