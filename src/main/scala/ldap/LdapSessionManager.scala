/*
 * Copyright (C) 2017  Roberto Leibman
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ldap

import java.net.InetSocketAddress
import akka.actor.ActorSystem
import scala.concurrent.duration._
import scala.language.postfixOps
import akka.actor.Actor
import akka.actor.Props
import akka.event.Logging
import akka.actor.Cancellable

case class LdapSession(userDN: String,
                       address: InetSocketAddress,
                       lastHeartBeat: Long,
                       cancellable: Cancellable) {
  val started = System.currentTimeMillis
  //TODO: we may want to add long operations here, so that we use the abandon operation
  //TODO: I'm not quite sure, but I think SASL auth may need some state saved here
  //TODO: Another piece of state may be paged searches
  //TODO: ???? BindStatus of Anonymous, Simple-auth Pending, Sasl pending or Authenticated
}

object LdapSessionManager extends Config {
  val name          = "sessionManager"
  val sessionMaxAge = 3 minutes
  val checkInterval = 1 minute

  trait Message
  case class StartSession(userDN: String, address: InetSocketAddress) extends Message
  case class ExpireSession(address: InetSocketAddress)
  case class EndSession(address: InetSocketAddress)
  case class SessionHeartbeat(address: InetSocketAddress)
  case class GetSession(address: InetSocketAddress)
  case object EndManager extends Message

  def start(implicit system: ActorSystem) = {
    import system.dispatcher
    val href = system.actorOf(Props(new LdapSessionManager()), "sessionManager")
    href
  }
}

class LdapSessionManager extends Actor {
  import LdapSessionManager._
  import context.dispatcher
  val log              = Logging(context.system, this)
  private val sessions = scala.collection.mutable.Map.empty[String, LdapSession]

  def receive = {
    case StartSession(userDN, address) =>
      log.info(s"Starting session for user ${userDN} from ${address} ")
      sessions += (
        address.toString() -> LdapSession(
          userDN,
          address,
          System.currentTimeMillis(),
          context.system.scheduler.scheduleOnce(sessionMaxAge, self, ExpireSession(address))
        )
      )
    case EndSession(address) =>
      log.info(s"Ending session from ${address} ")
      val removed = sessions.remove(address.toString())
    case SessionHeartbeat(address) =>
      log.info(s"Session heartbeat from ${address} ")
      val removed = sessions.remove(address.toString())
      removed.foreach { session =>
        session.cancellable.cancel()
        val cancellable = context.system.scheduler
          .scheduleOnce(sessionMaxAge, self, ExpireSession(address))
        sessions += (address.toString() -> session.copy(lastHeartBeat = System.currentTimeMillis(),
                                                        cancellable = cancellable))
      }
    case GetSession(address) =>
      sender ! sessions.get(address.toString())
    case ExpireSession(address) =>
      log.info(s"Session expired ${address} ")
      val removed = sessions.remove(address.toString())
    //TODO need to send notice of disconnection (https://tools.ietf.org/html/rfc4511#section-4.4.1) to the client
  }
}
