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

case object TLSExtendedRequest extends ExtendedRequest {
  override val oid = RFC2830Plugin.oid
}
case class TLSExtendedResponse(ldapResult: LdapResult, generatedPassword: Option[String])
    extends ExtendedResponse {}

object RFC2830Plugin extends Plugin {
  val oid = LDAPOID("1.3.6.1.4.1.1466.20037")

  override def decodeApplication(applicationAsn1: Asn1Application): Option[MessageProtocolOp] = {
    println("============================+++> Here")
    applicationAsn1.tag match {
      case 23 => //Extended
        println("============================+++> Here 2")
        applicationAsn1.value.toSeq match {
          case Seq(Asn1String(oid.value), _: Asn1String) ⇒
            Some(TLSExtendedRequest)
          case _ => None //Don't know this dude
        }
      case _ => None //Don't know this dude
    }
  }

}
