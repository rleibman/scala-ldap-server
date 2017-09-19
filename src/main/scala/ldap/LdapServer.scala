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
import com.typesafe.sslconfig.akka.AkkaSSLConfig
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.SSLContext
import java.security.SecureRandom
import akka.stream.TLSProtocol
import akka.stream.scaladsl.TLS
import akka.stream.TLSRole
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import akka.util.ByteString
import akka.stream.scaladsl.Flow
import com.typesafe.sslconfig.ssl.ClientAuth
import akka.stream.TLSClientAuth
import akka.stream.scaladsl.BidiFlow

class LdapListener extends Actor with Config {
  import context.system
  import akka.io.Tcp._

  def tlsStage = {
    val sslConfig = AkkaSSLConfig()
    val config    = sslConfig.config

    // create a ssl-context that ignores self-signed certificates
    implicit val sslContext: SSLContext = {
      object WideOpenX509TrustManager extends X509TrustManager {
        override def checkClientTrusted(chain: Array[X509Certificate], authType: String) = ()
        override def checkServerTrusted(chain: Array[X509Certificate], authType: String) = ()
        override def getAcceptedIssuers                                                  = Array[X509Certificate]()
      }

      val context = SSLContext.getInstance("TLS")
      context.init(Array[KeyManager](), Array(WideOpenX509TrustManager), null)
      context
    }
    // protocols
    val defaultParams    = sslContext.getDefaultSSLParameters()
    val defaultProtocols = defaultParams.getProtocols()
    val protocols        = sslConfig.configureProtocols(defaultProtocols, config)
    defaultParams.setProtocols(protocols)

    // ciphers
    val defaultCiphers = defaultParams.getCipherSuites()
    val cipherSuites   = sslConfig.configureCipherSuites(defaultCiphers, config)
    defaultParams.setCipherSuites(cipherSuites)

    val firstSession = new TLSProtocol.NegotiateNewSession(None, None, None, None)
      .withCipherSuites(cipherSuites: _*)
      .withProtocols(protocols: _*)
      .withParameters(defaultParams)

    val clientAuth = getClientAuth(config.sslParametersConfig.clientAuth)
    clientAuth map { firstSession.withClientAuth(_) }

    val tls = TLS(sslContext, firstSession, TLSRole.server)

    val pf: PartialFunction[TLSProtocol.SslTlsInbound, ByteString] = {
      case TLSProtocol.SessionBytes(_, sb) => ByteString.fromByteBuffer(sb.asByteBuffer)
    }

    val tlsSupport = BidiFlow.fromFlows(Flow[ByteString].map(TLSProtocol.SendBytes),
                                        Flow[TLSProtocol.SslTlsInbound].collect(pf));

    tlsSupport.atop(tls);
  }

  def getClientAuth(auth: ClientAuth) =
    if (auth.equals(ClientAuth.want)) {
      Some(TLSClientAuth.want)
    } else if (auth.equals(ClientAuth.need)) {
      Some(TLSClientAuth.need)
    } else if (auth.equals(ClientAuth.none)) {
      Some(TLSClientAuth.none)
    } else {
      None
    }

  val log = Logging(context.system, getClass)

  val host     = config.getString("scala-ldap-server.host")
  val port     = config.getInt("scala-ldap-server.port")
  val startTLS = config.getBoolean("scala-ldap-server.startTLS")

  IO(Tcp) ! Bind(self, new InetSocketAddress(host, port))

  def receive = {
    case _ @Bound(localAddress) ⇒
      log.info(s"bound to ${localAddress}")
    // do some logging or setup ...

    case CommandFailed(_: Bind) ⇒ context stop self

    case _ @Connected(remote, local) ⇒
      log.debug(s"Connected ${remote} to ${local}")
      val handler    = context.actorOf(LdapHandler.props(Some(remote)))
      val connection = sender()
      connection ! Register(handler)
  }
}

object LdapServer extends App with Config {
  // Create the actor system
  implicit val system = ActorSystem("scala-ldap-server")
  import system.dispatcher
  val log            = Logging(system, getClass)
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
                                 "cn"          -> List("Manager"),
                                 "description" -> List("Directory Manager")),
            parentId = Some(BaseNode.id)
          ),
          Node(
            id = "",
            dn = s"ou=Groups,${baseDN}",
            baseDN = baseDN,
            structuralObjectClass = "organizationalUnit",
            userAttributes =
              Map("objectClass" -> List("organizationalUnit"), "ou" -> List("groups")),
            parentId = Some(BaseNode.id)
          ),
          Node(
            id = "",
            dn = s"ou=People,${baseDN}",
            baseDN = baseDN,
            structuralObjectClass = "organizationalUnit",
            userAttributes =
              Map("objectClass" -> List("organizationalUnit"), "ou" -> List("people")),
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

  def shutdown() =
    system.terminate()
}
