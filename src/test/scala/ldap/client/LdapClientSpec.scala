package ldap.client

import akka.testkit.TestKit
import akka.testkit.ImplicitSender
import org.scalatest.BeforeAndAfterAll
import org.scalatest.FlatSpecLike
import akka.actor.ActorSystem
import org.scalatest.AsyncFlatSpecLike

class LdapClientSpec extends TestKit(ActorSystem("MySpec")) with AsyncFlatSpecLike with ImplicitSender with BeforeAndAfterAll {
  override def afterAll {
    TestKit.shutdownActorSystem(system)
  }

  "Valid authentication" should "authenticate validally" in {
    val config = LdapConfig2(
      host = "localhost",
      port = 1389,
      authSearchUser = "cn=admin,dc=example,dc=com",
      authSearchPassword = "123456789",
      authSearchBase = "ou=people,dc=example,dc=com",
      authSearchFilter = "")
    val auth = UserPass("testuser", "TestUserPassword")
    val clientFut = LdapClient(config, auth)
    clientFut.map { client =>
      assert(client != null)
    }
  }
}