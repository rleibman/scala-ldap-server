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
import java.util.UUID
import java.net.URI
import akka.util.ByteString

object LdapAsn1Decoder extends Config {
  private def encode(filter: Filter): Asn1ContextSpecific = filter match {
    case PresentFilter(str) => Asn1ContextSpecific(filter.filterType, str.getBytes)
    case EqualityMatchFilter(attributeDescription, attributeValue) =>
      val byteArray = BEREncoder.encode(Asn1Sequence(Asn1String(attributeDescription), Asn1String(attributeValue))).toArray
      Asn1ContextSpecific(filter.filterType, byteArray)
    //TODO 
    case _ => throw new Error(s"Unhandled Filter Type ${filter}")
  }
  private def decodeFilter(asn1ContextSpecific: Asn1ContextSpecific): Filter = {
    asn1ContextSpecific.tag match {
      case FilterType.present =>
        PresentFilter(asn1ContextSpecific.value.map(_.toChar).mkString)
      case FilterType.equalityMatch =>
        val attributeValueAssertion = BEREncoder.decode(ByteString(asn1ContextSpecific.value))
        attributeValueAssertion match {
          case List(Asn1String(attributeDescription), Asn1String(attributeValue)) =>
            EqualityMatchFilter(attributeDescription, attributeValue)
        }
      case _ => throw new Error(s"Unhandled Filter Type ${asn1ContextSpecific.tag}")
    }
  }

  def encode(msg: LdapMessage): Asn1Object = {
    val response: Seq[Asn1Object] = msg.protocolOp match {

      case request: SearchRequest =>
        //case class SearchRequest(
        //  baseObject: String,
        //  scope: SearchRequestScope = SearchRequestScope.singleLevel,
        //  derefAliases: DerefAliases = DerefAliases.derefAlways,
        //  sizeLimit: Int = Int.MaxValue,
        //  timeLimit: Int = Int.MaxValue,
        //  typesOnly: Boolean = false,
        //  filter: Option[Filter] = None,
        //  attributes: Seq[String] = Seq()
        //) extends Request
        List(
          Asn1Number(msg.messageId.toByte),
          Asn1Application(
            3,
            Asn1String(request.baseObject),
            Asn1Enumerated(request.scope.id),
            Asn1Enumerated(request.derefAliases.id),
            Asn1Int(request.sizeLimit),
            Asn1Int(request.timeLimit),
            Asn1Boolean(request.typesOnly),
            request.filter.fold(Asn1Null.asInstanceOf[Asn1Object])(encode),
            Asn1Sequence(request.attributes.map(Asn1String(_)): _*)
          )
        )
      case BindRequest(version: Int, name: String, authChoice: LdapAuthentication) =>
        val auth = authChoice match {
          case LdapSimpleAuthentication(password) => Asn1ContextSpecific(0, password.getBytes)
          case LdapSaslAuthentication(mech, creds) => Asn1ContextSpecific(3, mech.getBytes) //TODO missing creds
          case _ => throw new Error(s"I don't support ${authChoice.getClass} authentication")
        }
        List(Asn1Number(msg.messageId.toByte), Asn1Application(0, Asn1Int(version), Asn1String(name), auth))
      case _: Request =>
        throw new Error("Why are you trying to encode a request?, if you're working on the client you haven't yet coded this!")
      case BindResponse(LdapResult(opResult, matchedDN, diagnosticMessage, referral), serverSaslCreds) ⇒
        //TODO do something with referral and serverSaslCreds
        List(Asn1Number(msg.messageId.toByte), Asn1Application(1, Asn1Enumerated(opResult.code), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
      case SearchResultEntry(_: UUID, dn: String, attributes: Map[String, Seq[String]]) ⇒
        //Note that we ignore the uuid, the client doesn't know anything about it.
        val me = attributes.toSeq.map(tuple => Asn1Sequence(Asn1String(tuple._1), Asn1Set(tuple._2.map(Asn1String(_)): _*)))
        //        val me = attributes.toSeq.map(tuple => Asn1Sequence(Asn1String(tuple._1), Asn1Sequence(tuple._2.map(Asn1String(_)): _*)))
        val attSequence = Asn1Sequence(me: _*)
        List(Asn1Number(msg.messageId.toByte), Asn1Application(4, Asn1String(dn), attSequence))
      case SearchResultDone(LdapResult(opResult, matchedDN, diagnosticMessage, referral)) ⇒
        List(Asn1Number(msg.messageId.toByte), Asn1Application(5, Asn1Enumerated(opResult.code), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
      case SearchResultEntryReference() ⇒ throw new Error("Not yet supported")
      case SearchResultReference(_) ⇒ throw new Error("Not yet supported")
      case ModifyResponse(_) ⇒ throw new Error("Not yet supported")
      case AddResponse(LdapResult(opResult, matchedDN, diagnosticMessage, referral)) ⇒
        //TODO do something with referral
        List(Asn1Number(msg.messageId.toByte), Asn1Application(9, Asn1Enumerated(opResult.code), Asn1String(matchedDN), Asn1String(diagnosticMessage)))
      case DelResponse(_) ⇒ throw new Error("Not yet supported")
      case ModifyDNResponse(_) ⇒ throw new Error("Not yet supported")
      case CompareResponse(_) ⇒ throw new Error("Not yet supported")
      case _ =>
        val response = plugins.foldLeft(Option[Asn1Object](null))((acc, plugin) => acc.fold(plugin.encode(msg))(_ => acc))
        response.fold(throw new Error(s"${msg.protocolOp} protocol not supported and no plugin found"))(Seq(_))
    }
    val controls = msg.controls.map { control =>
      val res = plugins.foldLeft(Option[Asn1Object](null))((acc, plugin) => acc.fold(plugin.encodeControl(control))(_ => acc))
      res.fold(throw new Error(s"${control} not supported and no plugin found"))(identity)
    }
    Asn1Sequence((response ++ controls): _*)
  }
  def decode(asn1: Asn1Object): LdapMessage = {
    val seq = asn1.asInstanceOf[Asn1Sequence]
    val messageId: Long = seq.value(0) match {
      case Asn1Byte(value) ⇒ value.toLong
      case Asn1Short(value) ⇒ value.toLong
      case Asn1Int(value) ⇒ value.toLong
      case Asn1Long(value) ⇒ value
      case _ ⇒ throw new Error(s"Bad value of messageId ${seq.value(0)}")
    }

    val applicationAsn1 = seq.value(1).asInstanceOf[Asn1Application]
    val values = applicationAsn1.value.toSeq

    val operation: MessageProtocolOp = applicationAsn1.tag match {
      case 0 ⇒ {
        values match {
          case Seq(Asn1Number(version), Asn1String(name), Asn1ContextSpecific(_, password)) ⇒
            BindRequest(version.toInt, name, LdapSimpleAuthentication(password.map(_.toChar).mkString))
        }
      }
      case 2 ⇒
        UnbindRequest()
      case 3 ⇒ {
        val attributes = if (values.length > 7) {
          values(7).asInstanceOf[Asn1Sequence].value.map(_.asInstanceOf[Asn1String].value)
        } else {
          Seq.empty
        }
        SearchRequest(
          values(0).asInstanceOf[Asn1String].value,
          SearchRequestScope(values(1).asInstanceOf[Asn1Enumerated].value.toInt),
          DerefAliases(values(2).asInstanceOf[Asn1Enumerated].value.toInt),
          (values(3).asInstanceOf[Asn1Number[_ <: Number]]).value.intValue(),
          (values(4).asInstanceOf[Asn1Number[_ <: Number]]).value.intValue(),
          values(5).asInstanceOf[Asn1Boolean].value,
          Some(decodeFilter(values(6).asInstanceOf[Asn1ContextSpecific])),
          attributes
        )
      }
      case 6 ⇒
        ModifyRequest("", List.empty)
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 8 ⇒
        val attributes =
          values(1).asInstanceOf[Asn1Sequence].value.map {
            value1 =>
              (value1.asInstanceOf[Asn1Sequence].value(0).asInstanceOf[Asn1String].value, value1.asInstanceOf[Asn1Sequence].value(1).asInstanceOf[Asn1Set].value.map(_.asInstanceOf[Asn1String].value).toSeq)
          }.toMap
        AddRequest(values(0).asInstanceOf[Asn1String].value, attributes)
      case 10 ⇒
        DelRequest("")
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 12 ⇒
        ModifyDNRequest("", "", true)
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 14 ⇒
        CompareRequest("", "", "")
        throw new Error(s"Unhandled Ldap: Operation ${applicationAsn1.tag}")
      case 16 ⇒
        AbandonRequest(messageId: Long)
      case 4 =>
        val attributes =
          values(1).asInstanceOf[Asn1Sequence].value.map {
            value1 =>
              (value1.asInstanceOf[Asn1Sequence].value(0).asInstanceOf[Asn1String].value, value1.asInstanceOf[Asn1Sequence].value(1).asInstanceOf[Asn1Set].value.map(_.asInstanceOf[Asn1String].value).toSeq)
          }.toMap
        val uuid = null //The client doesn't know anything about uuid's in the server
        SearchResultEntry(uuid, values(0).asInstanceOf[Asn1String].value, attributes)
      case 5 =>
        val referral = if (values.length > 3) {
          (values(3).asInstanceOf[Seq[Asn1String]].map(aString => new URI(aString.value))).toList
        } else {
          List.empty
        }
        val result = LdapResult(LDAPResultType(values(0).asInstanceOf[Asn1Enumerated].value), values(1).asInstanceOf[Asn1String].value, values(2).asInstanceOf[Asn1String].value, referral)
        SearchResultDone(result)
      case 1 =>
        val referral = if (values.length > 3) {
          (values(3).asInstanceOf[Seq[Asn1String]].map(aString => new URI(aString.value))).toList
        } else {
          List.empty
        }
        val result = LdapResult(LDAPResultType(values(0).asInstanceOf[Asn1Enumerated].value), values(1).asInstanceOf[Asn1String].value, values(2).asInstanceOf[Asn1String].value, referral)
        BindResponse(result, None) //TODO add serverSaslCreds
      case 7 //ModifyResponse("")
        | 9 //AddResponse
        | 11 //DelResponse 
        | 13 // ModifyDNResponse
        | 15 //CompareResponse
        | 19 => // SearchResultReference
        throw new Error("Why are you trying to decode a response? If you're working on the client you haven't yet coded this!")
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
//
//request = List(Asn1Sequence(List(Asn1Byte(1), Asn1Application(3,List(Asn1String(), Asn1Enumerated(0), Asn1Enumerated(3), Asn1Int(0), Asn1Int(0)  , Asn1False, Asn1ContextSpecific(6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73))), Asn1Sequence(List(Asn1String(subschemaSubentry))))))
//
//request = List(Asn1Sequence(List(Asn1Byte(2), Asn1Application(3,List(Asn1String(), Asn1Enumerated(0), Asn1Enumerated(3), Asn1Byte(0), Asn1Byte(0), Asn1False, Asn1ContextSpecific(6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73), Asn1Sequence(List(Asn1String(subschemaSubentry))))))))
//requestMsg = LdapMessage(2,SearchRequest(,baseObject,derefAlways,0,0,false,Some(PresentFilter(objectClass)),List(subschemaSubentry)),List())
//
