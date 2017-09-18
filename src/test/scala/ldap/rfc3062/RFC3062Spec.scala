package ldap.rfc3062

import akka.testkit.ImplicitSender
import org.scalatest.BeforeAndAfterAll
import akka.testkit.TestKit
import org.scalatest.FlatSpecLike
import akka.actor.ActorSystem
import ldap.LdapHandler
import ldap.LdapMessage
import scala.concurrent.duration._
import scala.language.postfixOps
import ldap.LDAPResultType
import ldap.BaseNode

class RFC3062Spec
    extends TestKit(ActorSystem("MySpec"))
    with FlatSpecLike
    with ImplicitSender
    with BeforeAndAfterAll {
  val handler = system.actorOf(LdapHandler.props(None))
  override def afterAll = {
    system.stop(handler)
    TestKit.shutdownActorSystem(system)
  }

  "sending a simple password request change when user is empty" should "error out" in {
    val request = ChangePasswordRequest(userIdentity = "", oldPassword = "", newPassword = "")
    handler ! LdapMessage(
      123,
      request
    )

    val responseMsg = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    assert(responseMsg.size == 1)
    val response =
      responseMsg.head.protocolOp.asInstanceOf[ChangePasswordResponse]
    assert(response.ldapResult.opResult != LDAPResultType.success)
    assert(response.ldapResult.matchedDN == request.userIdentity)
  }
  "sending a simple password request change when user does not exist" should "error out" in {
    val request =
      ChangePasswordRequest(userIdentity = "non-existing", oldPassword = "", newPassword = "")
    handler ! LdapMessage(
      123,
      request
    )

    val responseMsg = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    assert(responseMsg.size == 1)
    val response =
      responseMsg.head.protocolOp.asInstanceOf[ChangePasswordResponse]
    assert(response.ldapResult.opResult != LDAPResultType.success)
    assert(response.ldapResult.matchedDN == request.userIdentity)
  }
  val existingUserDn = s"uid=roberto,ou=People,${BaseNode.dn}"
  "sending a simple password request change when password doesn't match" should "error out" in {
    val request =
      ChangePasswordRequest(userIdentity = existingUserDn, oldPassword = "", newPassword = "")
    handler ! LdapMessage(
      123,
      request
    )

    val responseMsg = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    assert(responseMsg.size == 1)
    val response =
      responseMsg.head.protocolOp.asInstanceOf[ChangePasswordResponse]
    assert(response.ldapResult.opResult != LDAPResultType.success)
    assert(response.ldapResult.matchedDN == request.userIdentity)
  }
  "sending a simple password request change when new password is ugly" should "error out" in {
    val request =
      ChangePasswordRequest(userIdentity = existingUserDn, oldPassword = "", newPassword = "aoeu")
    handler ! LdapMessage(
      123,
      request
    )

    val responseMsg = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    assert(responseMsg.size == 1)
    val response =
      responseMsg.head.protocolOp.asInstanceOf[ChangePasswordResponse]
    assert(response.ldapResult.opResult != LDAPResultType.success)
    assert(response.ldapResult.matchedDN == request.userIdentity)
  }
  "sending a simple password request" should "not error out" in {
    val request =
      ChangePasswordRequest(userIdentity = existingUserDn, oldPassword = "", newPassword = "aoeu")
    handler ! LdapMessage(
      123,
      request
    )

    val responseMsg = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    assert(responseMsg.size == 1)
    val response =
      responseMsg.head.protocolOp.asInstanceOf[ChangePasswordResponse]
    assert(response.ldapResult.opResult == LDAPResultType.success)
    assert(response.ldapResult.matchedDN == request.userIdentity)
    println("-------------------------------------------------------------------------------------")
    println(response.generatedPassword)
    assert(response.generatedPassword.isEmpty)
    //Bind to see if the password was actually changed
    fail()
  }
  "sending a simple password request with blank newPassword" should "not error out and return a new password" in {
    val request =
      ChangePasswordRequest(userIdentity = existingUserDn, oldPassword = "", newPassword = "")
    handler ! LdapMessage(
      123,
      request
    )

    val responseMsg = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    assert(responseMsg.size == 1)
    val response =
      responseMsg.head.protocolOp.asInstanceOf[ChangePasswordResponse]
    assert(response.ldapResult.opResult == LDAPResultType.success)
    assert(response.ldapResult.matchedDN == request.userIdentity)
    println("-------------------------------------------------------------------------------------")
    assert(response.generatedPassword.nonEmpty && response.generatedPassword.get.nonEmpty)
  }

}
