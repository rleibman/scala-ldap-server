/*
 * Copyright (C) 2017  Roberto Leibman
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ldap.rfc2830

import asn1.Asn1Application
import asn1.Asn1String
import ldap.ExtendedRequest
import ldap.ExtendedResponse
import ldap.LDAPOID
import ldap.LdapResult
import ldap.MessageProtocolOp
import ldap.Plugin
import asn1.Asn1ContextSpecific
import dao.DAO
import ldap.LdapMessage
import scala.concurrent.Future
import ldap.LDAPResultType

case object TLSExtendedRequest extends ExtendedRequest {
  override val oid = RFC2830Plugin.oid
}
case object TLSExtendedResponse extends ExtendedResponse {
  override val oid = Some(RFC2830Plugin.oid)
  override val ldapResult: LdapResult =
    LdapResult(LDAPResultType.success, "", "Returned TLS Response")
}

object RFC2830Plugin extends Plugin {
  val oid = LDAPOID("1.3.6.1.4.1.1466.20037")

  override def decodeApplication(applicationAsn1: Asn1Application): Option[MessageProtocolOp] =
    applicationAsn1.tag match {
      case 23 => //Extended
        applicationAsn1.value.toSeq match {
          case Seq(Asn1ContextSpecific(_, value)) =>
            val requestOid = value.map(_.toChar).mkString
            if (requestOid == oid.value)
              Some(TLSExtendedRequest)
            else
              None //Don't know this dude
          case Seq(Asn1String(oid.value), _: Asn1String) ⇒
            Some(TLSExtendedRequest)
          case _ => None //Don't know this dude
        }
      case _ => None //Don't know this dude
    }
  override def operate(msg: LdapMessage,
                       preResults: Seq[LdapMessage],
                       dao: DAO): Future[Seq[LdapMessage]] =
    msg.protocolOp match {
      case TLSExtendedRequest =>
        /*
          TODO If the Start TLS extended request was not successful, the resultCode
          will be one of:
            operationsError  (operations sequencing incorrect; e.g. TLS already established)
            protocolError    (TLS not supported or incorrect PDU structure)
            referral         (this server doesn't do TLS, try this one)
  	        unavailable      (e.g. some major problem with TLS, or server is shutting down)
	       *
         */
        Future.successful {
          preResults :+ LdapMessage(msg.messageId, TLSExtendedResponse)
        }
    }

}
