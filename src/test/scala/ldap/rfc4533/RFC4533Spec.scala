package ldap.rfc4533
import akka.testkit.TestKit
import akka.actor.ActorSystem
import org.scalatest.FlatSpecLike
import org.scalatest.BeforeAndAfterAll
import akka.actor.Props
import scala.concurrent.duration._
import akka.testkit.ImplicitSender
import akka.actor.actorRef2Scala
import ldap.DerefAliases
import ldap.LDAPResultType
import ldap.LdapHandler
import ldap.SearchRequestScope
import ldap.SearchResultDone
import ldap.SearchResultEntry
import ldap.SearchRequest
import ldap.LdapMessage
import ldap.StringFilter

class RFC4333Spec extends TestKit(ActorSystem("MySpec")) with FlatSpecLike with ImplicitSender with BeforeAndAfterAll {
  override def afterAll {
    TestKit.shutdownActorSystem(system)
  }

  "sending a sync operation" should "return good stuff" in {
    val handler = system.actorOf(Props[LdapHandler])
    val objectName = ""

    handler ! LdapMessage(
      123,
      SearchRequest(objectName, SearchRequestScope.baseObject, DerefAliases.derefAlways, 0, 0, false, Some(StringFilter("objectClass")), List("subschemaSubentry")),
      List(SyncRequestControl())
    )
    val response = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    response.foreach(msg ⇒ {
      assert(msg.messageId == 123)
      assert(msg.controls.size > 1)
    })
    assert(response.size == 2)
    val searchResultEntry = response(0).protocolOp.asInstanceOf[SearchResultEntry]
    assert(searchResultEntry.dn === objectName)
    val searchResultDone = response(1).protocolOp.asInstanceOf[SearchResultDone]
    assert(searchResultDone.ldapResult.opResult == LDAPResultType.success)
  }
}
