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

import java.net.InetSocketAddress
import java.time.format.DateTimeFormatter

import scala.concurrent.Await
import scala.concurrent.Future
import scala.concurrent.duration.DurationInt

import akka.actor.Actor
import akka.actor.ActorSystem
import akka.actor.Props
import akka.actor.actorRef2Scala
import akka.event.Logging
import akka.io.IO
import akka.io.Tcp
import akka.io.Tcp.Bind
import dao.MongoDAO
import ldap.rfc4533.RFC4533Plugin

//TODO add session management, currently each operation is coming by itself, they need to be
class LdapListener extends Actor with Config {
  import context.system
  import akka.io.Tcp._

  val log = Logging(context.system, getClass)

  val host = config.getString("scala-ldap-server.host")
  val port = config.getInt("scala-ldap-server.port")
  IO(Tcp) ! Bind(self, new InetSocketAddress(host, port))

  def receive = {
    case b @ Bound(localAddress) ⇒
      log.info(s"bound to ${localAddress}")
    // do some logging or setup ...

    case CommandFailed(_: Bind) ⇒ context stop self

    case c @ Connected(remote, local) ⇒
      log.debug(s"Connected ${remote} to ${local}")
      val handler = context.actorOf(Props[LdapHandler])
      val connection = sender()
      connection ! Register(handler)
  }
}

object LdapServer extends App with Config {
  // Create the actor system
  implicit val system = ActorSystem("scala-ldap-server")
  import system.dispatcher
  init()
  val plugins: Seq[Plugin] = Seq(RFC4533Plugin)
  val log = Logging(system, getClass)

  def init() = {
    val baseDN = config.getString("scala-ldap-server.base")
    val date = java.time.ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssZ"))

    def defaultOperationalAttributes(structuralObjectClass: String) = Map(
      "creatorsName" -> List(s"cn=Manager,${baseDN}"),
      "createTimestamp" -> List(date),
      "modifiersName" -> List(s"cn=Manager,${baseDN}"),
      "modifyTimestamp" -> List(date),
      "structuralObjectClass" -> List(structuralObjectClass)
    )

    val dao = new MongoDAO()
    val fut = for {
      root ← dao.getNode("")
      root2 ← if (root.isEmpty) {
        dao.update(Node(
          id = "",
          dn = "",
          operationalAttributes = defaultOperationalAttributes("ScalaLDAProotDSE") ++
          Map(
            "configContext" -> List("cn=config"),
            "monitorContext" -> List("cn=Monitor"),
            "namingContexts" -> List(baseDN),
            "supportedControl" -> plugins.flatMap(_.supportedControls.map(_.oid.value)),
            "supportedExtension" -> List(),
            "supportedFeatures" -> List(),
            "supportedLDAPVersion" -> List("3"),
            "supportedSASLMechanisms" -> List("LOGIN", "PLAIN"),
            "subschemaSubentry" -> List("cn=Subschema"),
            "altServer" -> List(),
            "entryDN" -> List("")
          ),
          userAttributes = Map(
            "objectClass" -> List("top", "ScalaLDAProotDSE"),
            "vendorName" -> List("scala-ldap-server"),
            "vendorVersion" -> List("0.0.2")
          ),
          parentId = None
        ))
      } else {
        Future.successful(root.get)
      }
      base ← dao.getNode(baseDN)
      base2 ← if (base.isEmpty) {
        dao.update(Node(
          id = "",
          dn = baseDN,
          operationalAttributes = defaultOperationalAttributes("organization"),
          userAttributes = Map(
            "objectClass" -> List("top", "dcObject", "organization"),
            "dc" -> List("example"),
            "o" -> List("example"),
            "ou" -> List("example"),
            "description" -> List("example")
          ),
          parentId = Some(root2.id)
        ))
      } else {
        Future.successful(base.get)
      }
      subschema ← dao.getNode("cn=Subschema")
      subschema2 ← if (subschema.isEmpty) {
        dao.update(Node(
          id = "",
          dn = "cn=Subschema",
          operationalAttributes = defaultOperationalAttributes("subentry"),
          userAttributes = Map(
            "objectClass" -> List("top", "subentry", "subschema", "extensibleObject"),
            "cn" -> List("Subschema"),
            "description" -> List("example")
          ),
          parentId = Some(root2.id)
        ))
      } else {
        Future.successful(base.get)
      }
      firstLevel ← {
        val firstLevelNodes = List(
          Node(id = "", dn = "cn=Manager", operationalAttributes = defaultOperationalAttributes("organizationalRole"), userAttributes = Map("objectClass" -> List("organizationalRole"), "cn" -> List("Manager"), "description" -> List("Directory Manager")), parentId = Some(base2.id)),
          Node(id = "", dn = "ou=Groups", operationalAttributes = defaultOperationalAttributes("organizationalUnit"), userAttributes = Map("objectClass" -> List("organizationalUnit"), "ou" -> List("groups")), parentId = Some(base2.id)),
          Node(id = "", dn = "ou=People", operationalAttributes = defaultOperationalAttributes("organizationalUnit"), userAttributes = Map("objectClass" -> List("organizationalUnit"), "ou" -> List("people")), parentId = Some(base2.id))
        )
        Future.sequence(firstLevelNodes.map { node ⇒
          for {
            gotNode ← dao.getNode(node.dn)
            updatedNode ← if (gotNode.isEmpty) { dao.update(node) } else { Future.successful(gotNode.get) }
          } yield (updatedNode)
        })
      }
      updatedRoot ← dao.update(root2.copy(children = List(subschema2.id, base2.id)))
    } yield (updatedRoot)

    val inited = Await.result(fut, 5 minutes)
  }

  // Create the 'ldap' actor
  val ldap = system.actorOf(Props[LdapListener], "ldap")
}
