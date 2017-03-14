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
import asn1.Asn1Object
import ldap.rfc4533.RFC4533Plugin
import java.util.UUID

object LdapAsn1Decoder {

  val plugins: Seq[Plugin] = Seq(RFC4533Plugin)

  def encode(msg: LdapMessage): Asn1Object = {
    val response = msg.protocolOp match {
      case request: Request =>
        throw new Error("Why are you trying to encode a request?, that doesn't make much sense")
      case BindResponse(LdapResult(opResult, matchedDN, diagnosticMessage, referral), serverSaslCreds) ⇒
        //TODO do something with referral and serverSaslCreds
        Asn1Sequence(Asn1Number(msg.messageId.toByte), Asn1Application(1, Asn1Enumerated(opResult.code), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
      case SearchResultEntry(id: UUID, dn: String, attributes: Map[String, Seq[String]]) ⇒
        Asn1Sequence(Asn1Number(msg.messageId.toByte), Asn1Application(4, Asn1String(dn)))
      case SearchResultDone(LdapResult(opResult, matchedDN, diagnosticMessage, referral)) ⇒
        Asn1Sequence(Asn1Number(msg.messageId.toByte), Asn1Application(5, Asn1Enumerated(opResult.code), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
      case SearchResultEntryReference() ⇒ throw new Error("Not yet supported")
      case SearchResultReference(_) ⇒ throw new Error("Not yet supported")
      case ModifyResponse(_) ⇒ throw new Error("Not yet supported")
      case AddResponse(_) ⇒ throw new Error("Not yet supported")
      case DelResponse(_) ⇒ throw new Error("Not yet supported")
      case ModifyDNResponse(_) ⇒ throw new Error("Not yet supported")
      case CompareResponse(_) ⇒ throw new Error("Not yet supported")
      case _ =>
        val response = plugins.foldLeft(Option[Asn1Object](null))((acc, plugin) => acc.fold(plugin.encode(msg))(_ => acc))
        response.fold(throw new Error(s"${msg.protocolOp} protocol not supported and no plugin found"))(identity)
    }
    val controls = msg.controls.map { control =>
      val res = plugins.foldLeft(Option[Asn1Object](null))((acc, plugin) => acc.fold(plugin.encodeControl(control))(_ => acc))
      res.fold(throw new Error(s"${control} not supported and no plugin found"))(identity)
    }
    Asn1Sequence((response +: controls): _*)
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
      case 0 ⇒ {
        applicationAsn1.value.toSeq match {
          case Seq(Asn1Byte(version), Asn1String(name), Asn1ContextSpecific(tag, password)) ⇒
            BindRequest(version, name, LdapSimpleAuthentication(password.map(_.toChar).mkString))
        }
      }
      case 2 ⇒
        UnbindRequest()
      case 3 ⇒ {
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
      case 6 ⇒
        ModifyRequest("")
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 8 ⇒
        AddRequest("")
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 10 ⇒
        DelRequest("")
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 12 ⇒
        ModifyDNRequest("")
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 14 ⇒
        CompareRequest("")
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 16 ⇒
        AbandonRequest(messageId: Long)
      case 1 //BindResponse
        | 4 //SearchResultEntry("")
        | 5 //SearchResultDone("")
        | 7 //ModifyResponse("")
        | 9 //AddResponse
        | 11 //DelResponse 
        | 13 // ModifyDNResponse
        | 15 //CompareResponse
        | 19 => // SearchResultReference
        throw new Error("Why are you trying to decode a response+, that doesn't make much sense")
      case _ ⇒ //ExtendedRequest, ExtendedResponse, IntermediateResponse 23 | 24 | 25
        val res = plugins.foldLeft(Option[MessageProtocolOp](null))((acc, plugin) => acc.fold(plugin.decodeApplication(applicationAsn1))(_ => acc))
        res.fold(throw new Error(s"Unknown Ldap: Operation ${applicationAsn1.tag}"))(identity)
    }

    //decode Controls
    val controls: Seq[Control] = seq.value.drop(2).map { controlAsn1 =>
      val res = plugins.foldLeft(Option[Control](null))((acc, plugin) => acc.fold(plugin.decodeControl(controlAsn1))(_ => acc))
      res.fold(throw new Error(s"Unknown Ldap Control: ${controlAsn1}"))(identity)
    }

    LdapMessage(messageId, operation, controls)
  }
}
