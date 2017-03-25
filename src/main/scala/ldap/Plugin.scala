package ldap

import asn1.Asn1Object
import asn1.Asn1Application
import scala.concurrent.Future

trait Plugin {
  def initialize(config: com.typesafe.config.Config): Future[Unit] = Future.successful {}
  def terminate(): Future[Unit] = Future.successful {}
  def resultTypes(): Seq[LDAPResultType] = Seq.empty
  def supportedControls: Seq[ldap.SupportedControl] = Seq.empty
  def encodeControl(control: Control): Option[Asn1Object] = None
  def encode(msg: LdapMessage): Option[Asn1Object] = None
  def decodeApplication(applicationAsn1: Asn1Application): Option[MessageProtocolOp] = None
  def decodeControl(controlAsn1: Asn1Object): Option[Control] = None
  def operate(msg: LdapMessage, preResults: Seq[LdapMessage]): Seq[LdapMessage] = preResults
}