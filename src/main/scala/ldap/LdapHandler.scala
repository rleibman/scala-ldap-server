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

import akka.actor.Actor
import asn1._
import akka.event.Logging
import akka.actor.actorRef2Scala
import akka.io.Tcp
import dao.MongoDAO
import akka.util.ByteString
import scala.concurrent.Future
import scala.concurrent.Await
import scala.concurrent.duration._

class LdapHandler extends Actor with Config {
  import context.dispatcher
  val dao = new MongoDAO()(context.system)
  import Tcp._
  import LDAPResultType._
  val log = Logging(context.system, getClass)
  def operate(msg: LdapMessage): Future[Seq[LdapMessage]] = {
    msg.protocolOp match {
      case BindRequest(version, name, authChoice) ⇒
        Future.successful { List(LdapMessage(msg.messageId, BindResponse(LdapResult(success, name, "Auth successful")))) }
      case UnbindRequest() ⇒
        Future.successful { List() }
      case SearchRequest(dn, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes) ⇒
        //        val dn = if (requestedDN.isEmpty) {
        //          config.getString("scala-ldap-server.base")
        //        } else {
        //          requestedDN
        //        }
        scope match {
          case SearchRequestScope.baseObject ⇒
            val nodeFut = dao.getNode(dn)
            nodeFut.map { nodeOpt ⇒
              nodeOpt match {
                case None ⇒ List(LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, "Search successful (no results found)"))))
                case Some(node) ⇒
                  List(
                    LdapMessage(msg.messageId, SearchResultEntry(node.dn, node.attributes)),
                    LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, "Search successful, one result found"))))
              }
            }
          case SearchRequestScope.singleLevel ⇒
            val children = for {
              top ← dao.getNode(dn)
              children ← dao.getChildren(top.get)
            } yield (children)

            Future.successful { List(LdapMessage(msg.messageId, SearchResultDone(LdapResult(operationsError, dn, "Not Yet implemented")))) }
          case SearchRequestScope.wholeSubtree ⇒
            Future.successful { List(LdapMessage(msg.messageId, SearchResultDone(LdapResult(operationsError, dn, "Not Yet implemented")))) }
        }

    }
  }

  import akka.pattern.pipe

  def receive = {
    case Received(data) ⇒
      //      println(data.map(b ⇒ s"0x${b.toHexString}"))
      val requestAsn1 = BEREncoder.decode(data)
      if (config.getBoolean("scala-ldap-server.logASN1")) {
        log.debug(s"request = ${requestAsn1}")
      }
      val requestMsg = LdapAsn1Decoder.decode(requestAsn1)
      if (config.getBoolean("scala-ldap-server.logLDAPRequest")) {
        log.debug(s"requestMsg = ${requestMsg}")
      }
      val responseMsgFut = operate(requestMsg)
      //      val theSender = sender() //Need to capture the sender, cause sender() is a var
      val fut = responseMsgFut.map { responseMsgs ⇒
        if (config.getBoolean("scala-ldap-server.logLDAPResponse")) {
          log.debug(s"responseMsgs = ${responseMsgs}")
        }
        val responseAsn1 = responseMsgs.map(LdapAsn1Decoder.encode)
        if (config.getBoolean("scala-ldap-server.logASN1")) {
          log.debug(s"response = ${responseAsn1}")
        }
        val responseDatas = responseAsn1.map(BEREncoder.encode)
        val responseData = responseDatas.foldLeft(ByteString())((a, b) ⇒ a ++ b)
        Write(responseData)
      }
      fut pipeTo sender()

    case PeerClosed ⇒ context stop self
  }
  //  import akka.pattern.pipe
  //  def receive = {
  //    val fut = somethingHappensLater()
  //    val fut2 = fut.map { responseData ⇒
  //      Write(responseData)
  //    }
  //    fut2 pipeTo sender()
  //  }
}
