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
import akka.actor.{ Actor, Props }
import akka.actor.ActorSystem
import akka.io.{ IO, Tcp }
import asn1._
import akka.actor.actorRef2Scala
import akka.io.Tcp.Bind
import akka.io.Tcp.Register
import dao.MongoDAO
import scala.concurrent.Await
import scala.concurrent.duration._
import scala.concurrent.Future

//TODO add session management, currently each operation is coming by itself, they need to be
class LdapListener extends Actor with Config {
  import Tcp._
  import context.system

  val host = config.getString("scala-ldap-server.host")
  val port = config.getInt("scala-ldap-server.port")
  IO(Tcp) ! Bind(self, new InetSocketAddress(host, port))

  def receive = {
    case b @ Bound(localAddress) ⇒
      println(s"bound to ${localAddress}")
    // do some logging or setup ...

    case CommandFailed(_: Bind) ⇒ context stop self

    case c @ Connected(remote, local) ⇒
      println(s"Connected ${remote} to ${local}")
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

  def init() = {
    val baseDN = config.getString("scala-ldap-server.base")
    val dao = new MongoDAO()
    val fut = for {
      root ← dao.getNode("")
      if (root.isEmpty)
      root2 ← dao.update(Node(id = "",
        dn = "",
        attributes = Map(
          "objectClass" -> List("top"),
          "configContext" -> List("cn=config"),
          "namingContexts" -> List(baseDN),
          "supportedLDAPVersion" -> List("3"),
          "supportedSASLMechanisms" -> List("LOGIN", "PLAIN")),
        parentId = None,
        children = Seq()))
      base ← dao.update(Node(id = "",
        dn = baseDN,
        attributes = Map(
          "objectClass" -> List("top", "dcObject", "organization"),
          "dc" -> List("example"),
          "o" -> List("example"),
          "ou" -> List("example"),
          "description" -> List("example")),
        parentId = Some(root2.id),
        children = Seq()))
      updatedRoot ← dao.update(root2.copy(children = List(base.id)))
    } yield (updatedRoot)

    val inited = Await.result(fut, 5 minutes)
  }

  // Create the 'ldap' actor
  val ldap = system.actorOf(Props[LdapListener], "ldap")
}
