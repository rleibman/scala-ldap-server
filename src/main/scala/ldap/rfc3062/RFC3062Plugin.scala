package ldap.rfc3062

import akka.util.ByteString
import ldap._
import asn1._
import scala.concurrent.Future
import dao.MongoDAO
import ldap.rfc3062.ChangePasswordRequest
import dao.DAO

/**
  * Implements operations defined in https://www.ietf.org/rfc/rfc3062.txt
  */
object RFC3062Plugin extends Plugin {

  val oid = LDAPOID("1.3.6.1.4.1.4203.1.11.1")
  val passwordPolicy = SimplePasswordPolicy //TODO make this dynamic and pluggable
  override def supportedExtensions: Seq[ldap.SupportedExtension] =
    Seq(SupportedExtension(oid, "Password ModifY Request"))

  override def decodeApplication(
      applicationAsn1: Asn1Application): Option[MessageProtocolOp] = {
    applicationAsn1.tag match {
      case 23 => //Extended
        applicationAsn1.value.toSeq match {
          case Seq(Asn1String(oid.value), details: Asn1String) ⇒
            val extended = BEREncoder.decode(ByteString(details.value))
            extended match {
              case List(Asn1String(userIdentity),
                        Asn1String(oldPassword),
                        Asn1String(requestedPassword)) =>
                Option(
                  ChangePasswordRequest(userIdentity,
                                        oldPassword,
                                        requestedPassword))
              case _ => None //Don't know this dude
            }
          case _ => None //Don't know this dude
        }
      case _ => None //Don't know this dude
    }
  }

  override def operate(msg: LdapMessage,
                       preResults: Seq[LdapMessage],
                       dao: DAO): Future[Seq[LdapMessage]] = Future.successful {
    msg.protocolOp match {
      case ChangePasswordRequest(userIdentity,
                                 oldPassword,
                                 requestedPassword) =>
        //TODO Do the password change
        // The userIdentity field, if present, SHALL contain an octet string
        // representation of the user associated with the request.  This string
        // may or may not be an LDAPDN [RFC2253].  If no userIdentity field is
        // present, the request acts up upon the password of the user currently
        // associated with the LDAP session. (Q: what LDAP session?)
        // TODO Implement password policy,
        // TODO Servers MAY implement administrative policies which restrict this operation.
        val generatedPassword = ""
        val valid =
          passwordPolicy.validatePassword(oldPassword, requestedPassword)
        val response = if (valid.isEmpty) {
          if (userIdentity.isEmpty()) {
            val result = LdapResult(
              LDAPResultType.noSuchObject,
              userIdentity,
              s"Could not change password: ${valid.mkString(".")}, user is empty")
            LdapMessage(msg.messageId, ChangePasswordResponse(result, None))
          } else {
            //All good, change the password
            if (requestedPassword.isEmpty && passwordPolicy.generatePasswordIfEmpty) {
              val generatedPassword = "" //TODO generate a password here
              //TODO save password
              val result = LdapResult(LDAPResultType.success,
                                      userIdentity,
                                      "Password changed successfully")
              LdapMessage(
                msg.messageId,
                ChangePasswordResponse(result, Some(generatedPassword)))
            } else if (requestedPassword.isEmpty) {
              val result = LdapResult(
                LDAPResultType.unwillingToPerform,
                userIdentity,
                s"Could not change password: You may not set the password to blank")
              LdapMessage(msg.messageId, ChangePasswordResponse(result, None))
            } else {
              //TODO save password
              val result = LdapResult(LDAPResultType.success,
                                      userIdentity,
                                      "Password changed successfully")
              LdapMessage(msg.messageId, ChangePasswordResponse(result, None))
            }
          }
        } else {
          val result =
            LdapResult(LDAPResultType.unwillingToPerform,
                       userIdentity,
                       s"Could not change password: ${valid.mkString(".")}")
          LdapMessage(msg.messageId, ChangePasswordResponse(result, None))
        }
        preResults :+ response

      case _ => preResults
    }
  }
}
