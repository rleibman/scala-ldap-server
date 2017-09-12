package ldap.client

import akka.testkit.TestKit
import akka.testkit.ImplicitSender
import org.scalatest.BeforeAndAfterAll
import akka.actor.ActorSystem
import org.scalatest.AsyncFlatSpecLike
import ldap._
import scala.concurrent.Future

class LdapClientSpec
    extends TestKit(ActorSystem("MySpec"))
    with AsyncFlatSpecLike
    with ImplicitSender
    with BeforeAndAfterAll {
  //  LdapServer.main(Array.empty)

  override def afterAll() = {
    //    LdapServer.shutdown()
    TestKit.shutdownActorSystem(system)
  }

  val config = LdapConfig(
    host = "localhost",
    port = 1389,
    authSearchUser = "cn=manager,dc=example,dc=com",
    authSearchPassword = "123456789",
    authSearchBase = "ou=people,dc=example,dc=com",
    authSearchFilter = ""
  )
  "Valid authentication" should "authenticate validally" in {
    val clientFut = LdapClient(config)
    clientFut.map { client =>
      assert(client != null)
    }
  }

  "Simple search 1" should "return some results" in {
    val request = SearchRequest(
      baseObject = "",
      scope = SearchRequestScope.baseObject,
      filter = Option(PresentFilter("objectClass")),
      attributes = Seq("subschemaSubentry")
    )
    for {
      client <- LdapClient(config)
      response <- client.fold(Future.successful(List[SearchResult]()))(client =>
        client.sendSearchRequest(request))
      asserted <- {
        println(response.head)
        assert(client != null)
        assert(response.nonEmpty)
        //        assert(response.last.isInstanceOf[SearchResultDone])
        //        assert(response.last.asInstanceOf[SearchResultDone].ldapResult.opResult == LDAPResultType.success)

      }
    } yield (asserted)
  }
  "Simple search 2" should "return some results" in {
    val request = SearchRequest(
      baseObject = "",
      scope = SearchRequestScope.baseObject,
      filter = Option(PresentFilter("objectClass")),
      attributes = Seq("*")
    )
    for {
      client <- LdapClient(config)
      response <- client.fold(Future.successful(List[SearchResult]()))(client =>
        client.sendSearchRequest(request))
      asserted <- {
        println(response.head)
        assert(client != null)
        assert(response.nonEmpty)
        //        assert(response.last.isInstanceOf[SearchResultDone])
        //        assert(response.last.asInstanceOf[SearchResultDone].ldapResult.opResult == LDAPResultType.success)

      }
    } yield (asserted)
  }
}
