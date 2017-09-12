package ldap.rfc4533
import akka.testkit.TestKit
import akka.actor.ActorSystem
import org.scalatest.FlatSpecLike
import org.scalatest.BeforeAndAfterAll
import akka.actor.Props
import scala.concurrent.duration._
import akka.testkit.ImplicitSender
import akka.actor.actorRef2Scala
import ldap._
import java.net.InetSocketAddress

class RFC4333Spec
    extends TestKit(ActorSystem("MySpec"))
    with FlatSpecLike
    with ImplicitSender
    with BeforeAndAfterAll {
  val handler = system.actorOf(LdapHandler.props(None))
  override def afterAll = {
    system.stop(handler)
    TestKit.shutdownActorSystem(system)
  }

  "3.3.1.  Initial Content Poll" should "return what the RFC says" in {
    val objectName = ""

    handler ! LdapMessage(
      123,
      SearchRequest(objectName,
                    SearchRequestScope.baseObject,
                    DerefAliases.derefAlways,
                    0,
                    0,
                    false,
                    Some(PresentFilter("objectClass")),
                    List("subschemaSubentry")),
      List(SyncRequestControl())
    )
    val response = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    assert(response.size == 2)
    val searchResultEntry =
      response(0).protocolOp.asInstanceOf[SearchResultEntry]
    assert(searchResultEntry.dn === objectName)
    val searchResultDone = response(1).protocolOp.asInstanceOf[SearchResultDone]
    assert(searchResultDone.ldapResult.opResult == LDAPResultType.success)
    response.foreach(msg ⇒ {
      msg.protocolOp match {
        case SearchResultEntry(uuid, dn, attributes) => {
          assert(msg.messageId == 123)
          assert(msg.controls.size == 1)
          val syncControl = msg.controls.head.asInstanceOf[SyncStateControl]
          assert(syncControl.syncStateValue == SyncStateType.add)
          assert(syncControl.cookie.nonEmpty)
        }
        case SearchResultEntryReference() => {
          assert(msg.messageId == 123)
          assert(msg.controls.size == 1)
          val syncControl = msg.controls.head.asInstanceOf[SyncStateControl]
          assert(syncControl.syncStateValue == SyncStateType.add)
          assert(syncControl.cookie.nonEmpty)
        }
        case SearchResultDone(result) => {
          assert(msg.messageId == 123)
          assert(msg.controls.size == 1)
          val syncControl = msg.controls.head.asInstanceOf[SyncDoneControl]
          assert(syncControl.refreshDeletes == false)
        }
      }
    })
  }

  "3.3.2.  Content Update Poll" should "be written" in {
    ???
  }
  "3.4.1.  refresh Stage" should "be written" in {
    ???
  }
  "3.4.2.  persist Stage" should "be written" in {
    ???
  }

}
