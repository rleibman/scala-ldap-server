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
import akka.actor.Actor
import asn1._
import akka.io.{ IO, Tcp }

class LdapHandler extends Actor {
  import Tcp._
  import LDAPResultType._

  def operate(msg: LdapMessage): LdapMessage = {
    msg.protocolOp match {
      case BindRequest(version, name, authChoice) ⇒
        LdapMessage(msg.messageId, BindResponse(LdapResult(success, name, "Auth successful")))
      case SearchRequest(baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes) ⇒
        LdapMessage(msg.messageId, BindResponse(LdapResult(success, baseObject, "Auth successful")))
    }
  }

  def receive = {
    case Received(data) ⇒
      //      println(data.map(b ⇒ s"0x${b.toHexString}"))
      val requestAsn1 = BEREncoder.decode(data)
      println(s"request = ${requestAsn1}")
      val requestMsg = LdapAsn1Decoder.decode(requestAsn1)
      println(s"requestMsg = ${requestMsg}")
      val responseMsg = operate(requestMsg)
      println(s"responseMsg = ${responseMsg}")
      val responseAsn1 = LdapAsn1Decoder.encode(responseMsg)
      println(s"response = ${responseAsn1}")
      val responseData = BEREncoder.encode(responseAsn1)

      sender() ! Write(responseData)
    case PeerClosed ⇒ context stop self
  }
}
