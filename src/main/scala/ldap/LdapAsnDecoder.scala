/*
 *   Copyright (C) 2016  Roberto Leibman
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package ldap

import asn1._

object LdapAsn1Decoder {
  def encode(msg: LdapMessage): Asn1Object = {
    msg.protocolOp match {
      case BindResponse(LdapResult(opResult, matchedDN, diagnosticMessage, referral), serverSaslCreds) ⇒
        //TODO do something with referral and serverSaslCreds
        Asn1Sequence(Asn1Number(msg.messageId.toByte), Asn1Application(1, Asn1Enumerated(opResult), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
      case SearchResultEntry(dn: String, attributes: Map[String, Seq[String]]) ⇒
        Asn1Sequence(Asn1Number(msg.messageId.toByte), Asn1Application(4, Asn1String(dn)))
      case SearchResultDone(LdapResult(opResult, matchedDN, diagnosticMessage, referral)) ⇒
        Asn1Sequence(Asn1Number(msg.messageId.toByte), Asn1Application(5, Asn1Enumerated(opResult), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
      case AbandonRequest(_) ⇒ throw new Error("Not yet supported")
      case BindRequest(_, _, _) ⇒ throw new Error("Not yet supported")
      case SearchRequest(_, _, _, _, _, _, _, _) ⇒ throw new Error("Not yet supported")
      case SearchResultEntryReference() ⇒ throw new Error("Not yet supported")
      case UnbindRequest() ⇒ throw new Error("Not yet supported")

    }
  }
  def decode(asn1: Asn1Object): LdapMessage = {
    val seq = asn1.asInstanceOf[Asn1Sequence]
    val messageId: Long = seq.value(0) match {
      case Asn1Byte(value) ⇒ value
      case Asn1Short(value) ⇒ value
      case Asn1Int(value) ⇒ value
      case Asn1Long(value) ⇒ value
      case _ ⇒ throw new Error(s"Bad value of messageId ${seq.value(0)}")
    }

    val applicationAsn1 = seq.value(1).asInstanceOf[Asn1Application]

    val operation: MessageProtocolOp = applicationAsn1.tag match {
      case 0 ⇒ { //bindRequest
        applicationAsn1.value.toSeq match {
          case Seq(Asn1Byte(version), Asn1String(name), Asn1ContextSpecific(tag, password)) ⇒
            BindRequest(version, name, LdapSimpleAuthentication(password.map(_.toChar).mkString))
        }
      }
      case 1 ⇒ //bindResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 2 ⇒ //unbindRequest
        UnbindRequest()
      case 3 ⇒ { //SearchRequest
        val seq = applicationAsn1.value.toSeq
        SearchRequest(
          seq(0).asInstanceOf[Asn1String].value,
          SearchRequestScope(seq(1).asInstanceOf[Asn1Enumerated].value),
          DerefAliases(seq(2).asInstanceOf[Asn1Enumerated].value),
          seq(3).asInstanceOf[Asn1Byte].value,
          seq(4).asInstanceOf[Asn1Byte].value,
          seq(5).asInstanceOf[Asn1Boolean].value,
          Some(StringFilter(seq(6).asInstanceOf[Asn1ContextSpecific].value.map(_.toChar).mkString)),
          seq(7).asInstanceOf[Asn1Sequence].value.map(_.asInstanceOf[Asn1String].value)
        )
      }
      case 4 ⇒ //SearchResultEntry
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 5 ⇒ //SearchResultDone
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 6 ⇒ //ModifyRequest
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 7 ⇒ //ModifyResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 8 ⇒ //AddRequest
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 9 ⇒ //AddResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 10 ⇒ //DelRequest
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 11 ⇒ //DelResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 12 ⇒ //ModifyDNRequest
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 13 ⇒ //ModifyDNResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 14 ⇒ //CompareRequest
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 15 ⇒ //CompareResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 16 ⇒ //AbandonRequest
        AbandonRequest(messageId: Long)
      case 19 ⇒ //SearchResultReference
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 23 ⇒ //ExtendedRequest
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 24 ⇒ //ExtendedResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 25 ⇒ //IntermediateResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case _ ⇒ throw new Error(s"Unknown Ldap: Operation ${applicationAsn1.tag}")
    }

    LdapMessage(messageId, operation)
  }
}
