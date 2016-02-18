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
import asn1._

object LdapAsn1Decoder {
  def encode(msg: LdapMessage): Asn1Object = {
    msg.protocolOp match {
      case BindResponse(LdapResult(opResult, matchedDN, diagnosticMessage, referral), serverSaslCreds) ⇒
        //TODO do something with referral and serverSaslCreds
        Asn1Sequence(Asn1Number(msg.messageId.toByte), Asn1Application(1, Asn1Enumerated(opResult), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
    }
  }
  def decode(asn1: Asn1Object): LdapMessage = {
    val seq = asn1.asInstanceOf[Asn1Sequence]
    val messageId: Long = seq.value(0) match {
      case Asn1Byte(value)  ⇒ value
      case Asn1Short(value) ⇒ value
      case Asn1Int(value)   ⇒ value
      case Asn1Long(value)  ⇒ value
      case _                ⇒ throw new Error(s"Bad value of messageId ${seq.value(0)}")
    }

    val applicationAsn1 = seq.value(1).asInstanceOf[Asn1Application]

    val operation: MessageProtocolOp = applicationAsn1.tag match {
      case 0 ⇒ { //bindRequest
        applicationAsn1.value.toSeq match {
          case Seq(Asn1Byte(version), Asn1String(name), Asn1ContextSpecific(password)) ⇒
            BindRequest(version, name, LdapSimpleAuthentication(password.map(_.toChar).mkString))
        }
      }
      case 1 ⇒ //bindResponse
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 2 ⇒ //unbindRequest
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 3 ⇒ { //SearchRequest
        //        request = Asn1Sequence(List(Asn1Byte(2), Asn1Application(3,List(Asn1String(), Asn1Enumerated(0), Asn1Enumerated(3), Asn1Byte(0), Asn1Byte(0), Asn1False, Asn1ContextSpecific(6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73)))))
        applicationAsn1.value.toSeq match {
          case Seq(Asn1String(baseObject), Asn1Enumerated(scope), Asn1Enumerated(derefAliases), Asn1Byte(sizeLimit), Asn1Byte(timeLimit), Asn1Boolean(typesOnly), Asn1ContextSpecific(filter)) ⇒
            SearchRequest(baseObject, SearchRequestScope(scope), DerefAliases(derefAliases), sizeLimit, timeLimit, typesOnly, Some(StringFilter(filter.map(_.toChar).mkString)))
        }
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
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
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
