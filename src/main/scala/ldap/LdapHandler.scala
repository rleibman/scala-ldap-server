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
import java.time.format.DateTimeFormatter
import scala.concurrent.duration._
import akka.io.Tcp.ConnectionClosed

class LdapHandler extends Actor with Config {
  import context.dispatcher
  val dao = new MongoDAO()(context.system)
  import LDAPResultType._
  import akka.io.Tcp._
  val log = Logging(context.system, getClass)

  override def postStop(): Unit = {
    log.debug("postStop, closing the driver")
    dao.connection.close()
    dao.driver.close()
  }

  def operate(msg: LdapMessage): Future[Seq[LdapMessage]] = {

    def filterAttributes(node: Node, requestedAttributes: Seq[String]) = {
      val operational = if (requestedAttributes.contains("+")) { //all operational
        node.operationalAttributes
      } else {
        node.operationalAttributes.filter(a ⇒ requestedAttributes.exists(_.compareToIgnoreCase(a._1) == 0))
      }
      val user = if (requestedAttributes.isEmpty) { //all of 'em
        node.userAttributes
      } else {
        node.userAttributes.filter(a ⇒ requestedAttributes.exists(_.compareToIgnoreCase(a._1) == 0))
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
        //TODO this
        Future.successful { List() }
      case BindRequest(version, name, authChoice) ⇒
        //TODO We need to actually do a login here, passing success always is not very secure :)
        //TODO version must be 3, or else bad!
        Future.successful { List(LdapMessage(msg.messageId, BindResponse(LdapResult(success, name, "Auth successful")))) }
      case UnbindRequest() ⇒
        Future.successful { List() }
      case SearchRequest(dn, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes) ⇒
        //        val dn = if (requestedDN.isEmpty) {
        //          config.getString("scala-ldap-server.base")
        //        } else {
        //          requestedDN
        //        }
        //TODO rfc3673: The presence of the attribute description "+" (ASCII 43) in the list of attributes
        //in a Search Request [RFC2251] SHALL signify a request for the return of all operational attributes.
        scope match {
          case SearchRequestScope.baseObject ⇒
            //limits the search scope to the object itself
            val nodeFut = dao.getNode(dn)
            nodeFut.map(_.fold(List(LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, "Search successful (no results found)")))))(node => List(
              LdapMessage(msg.messageId, SearchResultEntry(UUID.fromString(node.id), node.dn, filterAttributes(node, attributes))),
              LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, "Search successful, one result found")))
            )))
          case SearchRequestScope.singleLevel ⇒
            //limits the search scope to the object's immediate children
            val resultsFut = for {
              top ← dao.getNode(dn)
              children ← top.fold {
                Future.failed[List[Node]](new Error(s"No Parent present with dn=${dn}"))
              }(top => dao.getChildren(top))
            } yield (children)
            resultsFut.failed.foreach(_.printStackTrace())
            resultsFut.map(nodes ⇒ {
              val res = nodes.map(child ⇒ LdapMessage(msg.messageId, SearchResultEntry(UUID.fromString(child.id), child.dn, filterAttributes(child, attributes))))
              res :+ LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, s"Search successful, ${nodes.size} results found")))
            })
          case SearchRequestScope.wholeSubtree ⇒
            // limits the search scope to the object and all its descendants 
            val resultsFut = for {
              top ← dao.getNode(dn)
              children ← top.fold {
                Future.failed[List[Node]](new Error(s"No Parent present with dn=${dn}"))
              }(top => dao.getSubtree(top))
            } yield (top.toSeq ++ children)
            resultsFut.failed.foreach(_.printStackTrace())
            resultsFut.map(nodes ⇒ {
              val res = nodes.map(child ⇒ LdapMessage(msg.messageId, SearchResultEntry(UUID.fromString(child.id), child.dn, filterAttributes(child, attributes))))
              res :+ LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, s"Search successful, ${nodes.size} results found")))
            })
          case SearchRequestScope.children ⇒
            // limits the search scope to all of the descendants
            // This is available only on servers which support the LDAP Subordinates Search Scope extension. 
            // https://tools.ietf.org/html/draft-sermersheim-ldap-subordinate-scope-02
            val resultsFut = for {
              top ← dao.getNode(dn)
              children ← top.fold {
                Future.failed[List[Node]](new Error(s"No Parent present with dn=${dn}"))
              }(top => dao.getSubtree(top))
            } yield (children)
            resultsFut.failed.foreach(_.printStackTrace())
            resultsFut.map(nodes ⇒ {
              val res = nodes.map(child ⇒ LdapMessage(msg.messageId, SearchResultEntry(UUID.fromString(child.id), child.dn, filterAttributes(child, attributes))))
              res :+ LdapMessage(msg.messageId, SearchResultDone(LdapResult(success, dn, s"Search successful, ${nodes.size} results found")))
            })
        }
      case ModifyRequest(str, changes) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")
      case AddRequest(dn, attributes) =>
        //rfc4511 4.7
        val baseDN = config.getString("scala-ldap-server.base")
        val date = java.time.ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssZ"))
        val parentDN = dn.substring(dn.indexOf(","))
        for {
          exists <- dao.getNode(dn)
          parent <- dao.getNode(parentDN)
          result <- exists.fold {
            val saveMe = UserNode(
              id = "",
              dn = dn,
              userAttributes = Node.filterOutOperationalAttributes(attributes),
              creatorsName = attributes.getOrElse("creatorsName", Seq(s"cn=Manager,${baseDN}")).head,
              createTimeStamp = attributes.getOrElse("createTimeStamp", Seq(date)).head,
              modifiersName = attributes.getOrElse("modifiersName", Seq(s"cn=Manager,${baseDN}")).head,
              modifyTimestamp = attributes.getOrElse("modifyTimestamp", Seq(date)).head,
              structuralObjectClass = attributes.getOrElse("structuralObjectClass", Seq("subentry")).head,
              governingStructureRule = attributes.getOrElse("governingStructureRule", Seq("")).head,
              objectClass = attributes.getOrElse("objectClass", Seq.empty[String]).toList,
              attributeTypes = attributes.getOrElse("attributeTypes", Seq.empty[String]).toList,
              matchingRules = attributes.getOrElse("matchingRules", Seq.empty[String]).toList,
              distinguishedNameMatch = attributes.getOrElse("distinguishedNameMatch", Seq.empty[String]).toList,
              ldapSyntaxes = attributes.getOrElse("ldapSyntaxes", Seq.empty[String]).toList,
              matchingRuleUse = attributes.getOrElse("matchingRuleUse", Seq.empty[String]).toList,
              subschemaSubentry = attributes.getOrElse("subschemaSubentry", Seq("cn=Subschema")).head,
              parentId = parent.map(_.id)
            )
            dao.update(saveMe).map(_ => LdapResult(success, dn, s"$dn saved"))
          }(_ => Future.successful(LdapResult(entryAlreadyExists, dn, s"$dn already exists")))
        } yield (List(LdapMessage(msg.messageId, AddResponse(result))))
      case DelRequest(dn) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")
      case ModifyDNRequest(dn, newDN, deleteOld, newSuperiorDN) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")
      case CompareRequest(dn, attributeDescription, attributeValue) =>
        //TODO write this
        throw new Error(s"${msg.protocolOp} not handled")

      case _ ⇒ throw new Error(s"${msg.protocolOp} not handled")

    }

    fut.map { results: Seq[LdapMessage] =>
      plugins.foldLeft(results)((z, plugin) => plugin.operate(msg, z))
    }
  }

  import akka.pattern.pipe
  case object Ack extends Event
  def receive = {
    case data: ByteString =>
      sender() ! Write(data)
    case Received(data) ⇒
      val connection = sender()
      val list = BEREncoder.decode(data).toSeq
      if (config.getBoolean("scala-ldap-server.logASN1")) {
        log.debug(s"request = ${list}")
      }

      val fut = list.map { requestAsn1 =>
        val requestMsg = LdapAsn1Decoder.decode(requestAsn1)
        if (config.getBoolean("scala-ldap-server.logLDAPRequest")) {
          log.debug(s"requestMsg = ${requestMsg}")
        }
        operate(requestMsg).map { responseMsgs ⇒
          if (config.getBoolean("scala-ldap-server.logLDAPResponse")) {
            log.debug(s"responseMsgs = ${responseMsgs}")
          }
          val responseAsn1 = responseMsgs.map(LdapAsn1Decoder.encode)
          if (config.getBoolean("scala-ldap-server.logASN1")) {
            log.debug(s"response = ${responseAsn1}")
          }
          responseAsn1.map(BEREncoder.encode)
        }
      }
      val fut2 = Future.sequence(fut)
        .map(_.flatten.foldLeft(ByteString())((a, b) ⇒ a ++ b))
        .map(data => {
          connection ! Write(data)
        })
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
    case PeerClosed ⇒
      context stop self
    case _: ConnectionClosed =>
      context stop self
    case CommandFailed(w: Write) =>
      context stop self
  }
}
