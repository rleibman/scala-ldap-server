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
import scala.language.postfixOps

class LdapListener extends Actor with Config {
  import context.system
  import akka.io.Tcp._

  val log = Logging(context.system, getClass)

  val host = config.getString("scala-ldap-server.host")
  val port = config.getInt("scala-ldap-server.port")
  IO(Tcp) ! Bind(self, new InetSocketAddress(host, port))

  def receive = {
    case _ @Bound(localAddress) ⇒
      log.info(s"bound to ${localAddress}")
    // do some logging or setup ...

    case CommandFailed(_: Bind) ⇒ context stop self

    case _ @Connected(remote, local) ⇒
      log.debug(s"Connected ${remote} to ${local}")
      val handler = context.actorOf(LdapHandler.props(Some(remote)))
      val connection = sender()
      connection ! Register(handler)
  }
}

object LdapServer extends App with Config {
  // Create the actor system
  implicit val system = ActorSystem("scala-ldap-server")
  import system.dispatcher
  val log = Logging(system, getClass)
  val sessionManager = LdapSessionManager.start

  init()

  def init() = {
    val dao = new MongoDAO()
    val fut = for {
      firstLevel ← {
        val firstLevelNodes = List(
          Node(
            id = "",
            dn = s"cn=Manager,${baseDN}",
            baseDN = baseDN,
            structuralObjectClass = "organizationalRole",
            userAttributes = Map("objectClass" -> List("organizationalRole"),
                                 "cn" -> List("Manager"),
                                 "description" -> List("Directory Manager")),
            parentId = Some(BaseNode.id)
          ),
          Node(
            id = "",
            dn = s"ou=Groups,${baseDN}",
            baseDN = baseDN,
            structuralObjectClass = "organizationalUnit",
            userAttributes = Map("objectClass" -> List("organizationalUnit"),
                                 "ou" -> List("groups")),
            parentId = Some(BaseNode.id)
          ),
          Node(
            id = "",
            dn = s"ou=People,${baseDN}",
            baseDN = baseDN,
            structuralObjectClass = "organizationalUnit",
            userAttributes = Map("objectClass" -> List("organizationalUnit"),
                                 "ou" -> List("people")),
            parentId = Some(BaseNode.id)
          )
        )
        Future.sequence(firstLevelNodes.map { node ⇒
          for {
            gotNode ← dao.getNode(node.dn)
            updatedNode ← if (gotNode.isEmpty) { dao.update(node) } else {
              Future.successful(gotNode.get)
            }
          } yield (updatedNode)
        })
      }
      pluginInits <- Future.traverse(plugins)(_.initialize(config))
    } yield (firstLevel)

    Await.result(fut, 5 minutes)
  }

  // Create the 'ldap' actor
  val ldap = system.actorOf(Props[LdapListener], "ldap")

  def shutdown() = {
    system.terminate()
  }
}
