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

package ldap.client

import ldap._
import asn1.BEREncoder
import akka.actor.{ Actor, ActorSystem, Props }
import akka.io.{ IO, Tcp }
import java.net.InetSocketAddress
import scala.concurrent.Future
import scala.concurrent.Promise
import akka.actor.Stash
import scala.concurrent.duration._

case class LdapConfig(
    host: String,
    port: Int,
    authSearchUser: String,
    authSearchPassword: String,
    authSearchBase: String,
    authSearchFilter: String
)

object LdapClient {
  object TcpClient {
    def props(remote: InetSocketAddress,
              promise: Promise[List[LdapMessage]],
              checkReady: LdapMessage => Boolean) =
      Props(classOf[TcpClient], remote, promise, checkReady)
  }
  case object Timeout
  class TcpClient(remote: InetSocketAddress,
                  promise: Promise[List[LdapMessage]],
                  checkReady: LdapMessage => Boolean)
      extends Actor
      with Stash {
    import Tcp._
    import context.system
    val acc = scala.collection.mutable.ListBuffer[LdapMessage]()

    IO(Tcp) ! Connect(remote)
    //TODO figure out how to implement a client timeout,
    //Possibly start a timer when first calling Write, and restart it every time we receieve data
    //Then when triggered, call a timeout.i
    //    val cancelTimeout = system.scheduler.scheduleOnce(5 minutes, self, Timeout)(executor = system.dispatcher)
    //    cancelTimeout

    def receive = {
      case CommandFailed(_: Connect) =>
        promise.failure(new Error("Write failed"))
        context stop self

      case c @ Connected(remote, local) =>
        val connection = sender()
        connection ! Register(self)
        unstashAll()
        context become {
          case msg: LdapMessage =>
            val asn1Request = LdapAsn1Decoder.encode(msg)
            val bareRequest = BEREncoder.encode(asn1Request)
            connection ! Write(bareRequest)
          case CommandFailed(w: Write) =>
            // O/S buffer was full
            promise.failure(new Error("Write failed"))
            ()
          case Received(data) =>
            val asn1Response = BEREncoder.decode(data)
            val responses    = asn1Response.map(LdapAsn1Decoder.decode)
            acc ++= responses
            responses.foreach { response =>
              if (checkReady(response)) {
                promise.success(acc.toList)
              }
            }
            ()
          case "close" =>
            connection ! Close
            promise.failure(
              new Error(s"I really don't know how this was closed without receiving anything")
            )
            ()
          case a: ConnectionClosed =>
            context stop self
            //            promise.failure(new Error(s"I really don't know how this was closed without receiving anything: ${a}"))
            ()
        }
      case a =>
        //        promise.failure(new Error(s"I really don't know how I got here: ${a}"))
        stash()

    }
  }
  private def sendMessage(config: LdapConfig, msg: LdapMessage, checkReady: LdapMessage => Boolean)(
      implicit system: ActorSystem
  ): Future[List[LdapMessage]] = {
    val promise = Promise[List[LdapMessage]]()
    val client = system.actorOf(
      TcpClient.props(new InetSocketAddress(config.host, config.port), promise, checkReady)
    )
    client ! msg
    promise.future
  }

  /**
    * Authentication against an LDAP server is done in two separate steps:
    * First, some "search credentials" are used to log into the LDAP server and perform a search for the directory entry
    * matching a given user name. If exactly one user entry is found another LDAP bind operation is performed using the
    * principal DN of the found user entry to validate the password.
    */
  //case class SearchRequest(
  //  baseObject: String,
  //  scope: SearchRequestScope,
  //  derefAliases: DerefAliases,
  //  sizeLimit: Int,
  //  timeLimit: Int,
  //  typesOnly: Boolean,
  //  filter: Option[Filter] = None,
  //  attributes: Seq[String] = Seq()
  //) extends Request
  //case class BindRequest(version: Byte, name: String, authChoice: LdapAuthentication) extends Request
  def apply(config: LdapConfig)(implicit system: ActorSystem): Future[Option[LdapClient]] = {
    import system.dispatcher
    val fut = for {
      bindResponse <- {
        val msg = LdapMessage(
          1,
          BindRequest(3, config.authSearchUser, LdapSimpleAuthentication(config.authSearchPassword))
        )
        sendMessage(config, msg, { _.protocolOp.isInstanceOf[BindResponse] })
          .map(_.head.protocolOp.asInstanceOf[BindResponse])
      }
      ldapClient <- bindResponse.ldapResult.opResult match {
        case LDAPResultType.success =>
          Future.successful(Some(new LdapClient(config)))
        case LDAPResultType.invalidCredentials | LDAPResultType.inappropriateAuthentication |
            LDAPResultType.authMethodNotSupported | LDAPResultType.strongerAuthRequired =>
          //I separate this because they're specific to binding
          println(bindResponse.ldapResult.diagnosticMessage)
          Future.successful(None)
        case _ =>
          println(bindResponse.ldapResult.diagnosticMessage)
          Future.successful(None)
      }
    } yield (ldapClient)
    fut.recover {
      case t =>
        t.printStackTrace()
        None
    }
  }
}

class LdapClient(val config: LdapConfig)(implicit system: ActorSystem) {
  import system.dispatcher
  var counter = 1L

  def sendSearchRequest(request: SearchRequest): Future[List[SearchResult]] = {
    val msgRequest = LdapMessage(counter, request)
    counter = counter + 1
    val fut = LdapClient.sendMessage(config, msgRequest, {
      _.protocolOp.isInstanceOf[SearchResultDone]
    })
    fut.map(msg => msg.map(_.protocolOp.asInstanceOf[SearchResult]))
  }
}
