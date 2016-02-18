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
import java.net.InetSocketAddress

import akka.actor.{ Actor, Props }
import akka.actor.ActorSystem
import akka.io.{ IO, Tcp }
import asn1._

class LdapListener extends Actor {
  import Tcp._
  import context.system

  IO(Tcp) ! Bind(self, new InetSocketAddress("localhost", 1389))

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

object LdapServer extends App {
  // Create the 'helloakka' actor system
  val system = ActorSystem("ldap-server")

  // Create the 'ldap' actor
  val ldap = system.actorOf(Props[LdapListener], "ldap")
}
