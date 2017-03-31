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

import java.util.UUID

import scala.concurrent.Future

import akka.actor.Actor
import akka.event.Logging
import akka.util.ByteString
import asn1.BEREncoder
import dao.MongoDAO

class LdapHandler extends Actor with Config {
  import context.dispatcher
  val dao = new MongoDAO()(context.system)
  import LDAPResultType._
  import akka.io.Tcp._
  val log = Logging(context.system, getClass)

  override def postStop(): Unit = {
    dao.driver.close()
  }

  def operate(msg: LdapMessage): Future[Seq[LdapMessage]] = {

    def filterAttributes(node: Node, requestedAttributes: Seq[String]) = {
      val operational = if (requestedAttributes.contains("+")) { //all operational
        node.operationalAttributes
      } else {
        node.operationalAttributes.filter(a ⇒ requestedAttributes.contains(a._1))
      }
      val user = if (requestedAttributes.isEmpty) { //all of 'em
        node.userAttributes
      } else {
        node.userAttributes.filter(a ⇒ requestedAttributes.contains(a._1))
      }
      user ++ operational
    }

    val fut = msg.protocolOp match {
      case AbandonRequest(messageId) ⇒
        /*
         *  The function of the Abandon operation is to allow a client to request that the server abandon an uncompleted operation.
         *  The MessageID is that of an operation that was requested earlier at this LDAP message layer.
         *  The Abandon request itself has its own MessageID.  This is distinct from the MessageID of the earlier operation being abandoned.
         *  There is no response defined in the Abandon operation.
         *  Upon receipt of an AbandonRequest, the server MAY abandon the operation identified by the MessageID.  b
         *  Since the client cannot tell the difference between a successfully abandoned operation and an uncompleted operation,
         *  the application of the Abandon operation is limited to uses where the client does not require an indication of its outcome.
         *
         */
        Future.successful { List() }
      case BindRequest(version, name, authChoice) ⇒
        //TODO We need to actually do a login here, passing success always is not very secure :) 
        Future.successful { List(LdapMessage(msg.messageId, BindResponse(LdapResult(success, name, "Auth successful")))) }
      case UnbindRequest() ⇒
        Future.successful { List() }
      case SearchRequest(dn, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes) ⇒
        //        val dn = if (requestedDN.isEmpty) {
        //          config.getString("scala-ldap-server.base")
        //        } else {
        //          requestedDN
        //        }
        val bareDN = dn.replaceAll(s",${config.getString("scala-ldap-server.base")}", "").trim()
        //TODO rfc3673: The presence of the attribute description "+" (ASCII 43) in the list of attributes
        //in a Search Request [RFC2251] SHALL signify a request for the return of all operational attributes.
        scope match {
          case SearchRequestScope.baseObject ⇒
            val nodeFut = dao.getNode(bareDN)
            nodeFut.map(_.fold(List(LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, bareDN, "Search successful (no results found)")))))(node => List(
              LdapMessage(msg.messageId, SearchResultEntry(UUID.fromString(node.id), node.dn, filterAttributes(node, attributes))),
              LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, "Search successful, one result found")))
            )))
          case SearchRequestScope.singleLevel ⇒
            val childrenFut = for {
              top ← dao.getNode(bareDN)
              children ← top.fold {
                Future.failed[List[Node]](new Error(s"No Parent present with dn=${dn}"))
              }(top => dao.getChildren(top))
            } yield (children)
            childrenFut.failed.foreach(_.printStackTrace())
            childrenFut.map(children ⇒ {
              val res = children.map(child ⇒ LdapMessage(msg.messageId, SearchResultEntry(UUID.fromString(child.id), child.dn, filterAttributes(child, attributes))))
              res :+ LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, s"Search successful, ${children.size} results found")))
            })
          case SearchRequestScope.wholeSubtree ⇒
            Future.successful { List(LdapMessage(msg.messageId, SearchResultDone(LdapResult(operationsError, dn, "Not Yet implemented")))) }
        }
      case ModifyRequest(str) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")
      case AddRequest(str) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")
      case DelRequest(str) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")
      case ModifyDNRequest(str) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")
      case CompareRequest(str) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")

      case _ ⇒ throw new Error(s"${msg.protocolOp} not handled")

    }

    fut.map { results: Seq[LdapMessage] =>
      plugins.foldLeft(results)((z, plugin) => plugin.operate(msg, z))
    }
  }

  import akka.pattern.pipe

  def receive = {
    case Received(data) ⇒
      val list = BEREncoder.decode(data)
      if (config.getBoolean("scala-ldap-server.logASN1")) {
        log.debug(s"request = ${list}")
      }

      list.foreach { requestAsn1 =>
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
      }
      ()
    case msg: LdapMessage ⇒ {
      val fut = operate(msg)
      fut.foreach {
        res ⇒
          println(res)
      }
      fut pipeTo sender()
      ()
    }
    case PeerClosed ⇒ context stop self
  }
}
