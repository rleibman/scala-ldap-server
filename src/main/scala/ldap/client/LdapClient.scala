package ldap.client

import ldap._
import asn1.BEREncoder
import akka._
import akka.actor.{ Actor, ActorRef, Props, ActorSystem }
import akka.io.{ IO, Tcp }
import akka.util.ByteString
import java.net.InetSocketAddress
import scala.concurrent.Future
import scala.concurrent.Promise

case class UserPass(user: String, pass: String)

case class LdapConfig2(
  host: String,
  port: Int,
  authSearchUser: String,
  authSearchPassword: String,
  authSearchBase: String,
  authSearchFilter: String
)

object LdapClient {
  object TcpClient {
    def props(remote: InetSocketAddress, promise: Promise[ByteString]) =
      Props(classOf[TcpClient], remote, promise)
  }
  class TcpClient(remote: InetSocketAddress, promise: Promise[ByteString]) extends Actor {
    import Tcp._
    import context.system

    IO(Tcp) ! Connect(remote)

    def receive = {
      case CommandFailed(_: Connect) =>
        promise.failure(new Error("Write failed"))
        context stop self

      case c @ Connected(remote, local) =>
        val connection = sender()
        connection ! Register(self)
        context become {
          case data: ByteString =>
            connection ! Write(data)
          case CommandFailed(w: Write) =>
            // O/S buffer was full
            promise.failure(new Error("Write failed"))
          case Received(data) =>
            promise.success(data)
          case "close" =>
            connection ! Close
            promise.failure(new Error(s"I really don't know how this was closed without receiving anything"))
          case a: ConnectionClosed =>
            context stop self
            promise.failure(new Error(s"I really don't know how this was closed without receiving anything: ${a}"))
        }
      case a => promise.failure(new Error(s"I really don't know how I got here: ${a}"))
    }
  }
  def sendMessage(config: LdapConfig2, msg: LdapMessage)(implicit system: ActorSystem): Future[LdapMessage] = {
    import system.dispatcher
    val asn1Request = LdapAsn1Decoder.encode(msg)
    val bareRequest = BEREncoder.encode(asn1Request)
    val promise = Promise[ByteString]()
    val client = system.actorOf(TcpClient.props(new InetSocketAddress(config.host, config.port), promise))
    client ! bareRequest
    promise.future.map {
      bareResponse =>
        val asn1Response = BEREncoder.decode(bareResponse)
        val response = LdapAsn1Decoder.decode(asn1Response)
        response
    }
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
  def apply(config: LdapConfig2, userPass: UserPass)(implicit system: ActorSystem): Future[LdapClient] = {
    import system.dispatcher
    import LdapResult._
    val fut = for {
      foundUserMsg <- {
        val msg = LdapMessage(1, SearchRequest(baseObject = config.authSearchBase, filter = Some(PresentFilter(config.authSearchFilter))))
        sendMessage(config, msg)
      }
      boundUserMsg <- {
        val searchResultDone = foundUserMsg.protocolOp.asInstanceOf[SearchResultDone]
        if (searchResultDone.ldapResult != LDAPResultType.success)
          throw new Error("Bad authentication, Bad!")
        val msg = LdapMessage(2, BindRequest(3, "foundUser", LdapSimpleAuthentication(userPass.pass)))
        sendMessage(config, msg)
      }
    } yield (boundUserMsg)
    fut.map(_ => new LdapClient())
  }
}

class LdapClient {

}