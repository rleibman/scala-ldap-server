package ldap
import akka.testkit.TestKit
import akka.actor.ActorSystem
import org.scalatest.FlatSpecLike
import org.scalatest.BeforeAndAfterAll
import akka.actor.Props
import scala.concurrent.duration._
import akka.testkit.ImplicitSender

class LdapHandlerSpec extends TestKit(ActorSystem("MySpec")) with FlatSpecLike with ImplicitSender with BeforeAndAfterAll {
  override def afterAll {
    TestKit.shutdownActorSystem(system)
  }
  "sending a proper bindrequest" should "return a bindresponse" in {
    val handler = system.actorOf(Props[LdapHandler])
    handler ! LdapMessage(123, BindRequest(3, "cn=Manager,dc=example,dc=com", LdapSimpleAuthentication("password")))
    val response = expectMsg(List(LdapMessage(123, BindResponse(LdapResult(LDAPResultType.success, "cn=Manager,dc=example,dc=com", "Auth successful", List()), None))))
  }

  //case class SearchRequest(baseObject: String, scope: SearchRequestScope, derefAliases: DerefAliases, sizeLimit: Int, timeLimit: Int, typesOnly: Boolean, filter: Option[Filter] = None, attributes: Seq[String] = Seq()) extends MessageProtocolOp

  "sending a searchRequest for the base object" should "return a searchEntry and a searchDone" in {
    val handler = system.actorOf(Props[LdapHandler])
    val objectName = ""
    handler ! LdapMessage(123, SearchRequest(objectName, SearchRequestScope.baseObject, DerefAliases.derefAlways, 0, 0, false, Some(StringFilter("objectClass")), List("subschemaSubentry")))
    val response = expectMsgClass(1 minute, classOf[List[LdapMessage]])
    response.foreach(msg ⇒ assert(msg.messageId == 123))
    assert(response.size == 2)
    val searchResultEntry = response(0).protocolOp.asInstanceOf[SearchResultEntry]
    assert(searchResultEntry.dn === objectName)
    val searchResultDone = response(1).protocolOp.asInstanceOf[SearchResultDone]
    assert(searchResultDone.ldapResult.opResult == LDAPResultType.success)

    assert(searchResultEntry.attributes.nonEmpty)
    assert(searchResultEntry.attributes("subschemaSubentry").nonEmpty)
    assert(searchResultEntry.attributes("subschemaSubentry").head === "cn=Subschema")

    println(response)
  }

  "sending a searchRequest for the schema object" should "return a searchEntry and a searchDone" in {
    val handler = system.actorOf(Props[LdapHandler])
    val objectName = "cn=Subschema"
    handler ! LdapMessage(123, SearchRequest(objectName, SearchRequestScope.baseObject, DerefAliases.derefAlways, 0, 0, false, Some(StringFilter("objectClass=subschema")), List("createTimestamp", "modifyTimestamp")))
    val response = expectMsgClass(1 minute, classOf[List[LdapMessage]])

    response.foreach(msg ⇒ assert(msg.messageId == 123))
    assert(response.size == 2)
    val searchResultEntry = response(0).protocolOp.asInstanceOf[SearchResultEntry]
    assert(searchResultEntry.dn === objectName)
    val searchResultDone = response(1).protocolOp.asInstanceOf[SearchResultDone]
    assert(searchResultDone.ldapResult.opResult == LDAPResultType.success)

    assert(searchResultEntry.attributes.size === 2)
    assert(searchResultEntry.attributes("createTimestamp").nonEmpty)
    assert(searchResultEntry.attributes("createTimestamp").head.nonEmpty)

    assert(searchResultEntry.attributes("modifyTimestamp").nonEmpty)
    assert(searchResultEntry.attributes("modifyTimestamp").head.nonEmpty)

    println(response)
  }

  "sending a searchRequest for some base stuff" should "return a searchEntry and a searchDone" in {
    val handler = system.actorOf(Props[LdapHandler])
    val objectName = ""
    handler ! LdapMessage(123, SearchRequest(objectName,
      SearchRequestScope.baseObject,
      DerefAliases.neverDerefAliases,
      0,
      0,
      false,
      Some(StringFilter("objectClass")),
      List("namingContexts",
        "subschemaSubentry",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
        "supportedExtension",
        "supportedControl",
        "supportedFeatures",
        "vendorName",
        "vendorVersion",
        "+",
        "objectClass")))
    val response = expectMsgClass(1 minute, classOf[List[LdapMessage]])

    response.foreach(msg ⇒ assert(msg.messageId == 123))
    assert(response.size == 2)
    val searchResultEntry = response(0).protocolOp.asInstanceOf[SearchResultEntry]
    assert(searchResultEntry.dn === objectName)
    val searchResultDone = response(1).protocolOp.asInstanceOf[SearchResultDone]
    assert(searchResultDone.ldapResult.opResult == LDAPResultType.success)

    //    assert(searchResultEntry.attributes.nonEmpty1)

    assert(searchResultEntry.attributes("objectClass").size === 2)
    assert(searchResultEntry.attributes("objectClass").head.nonEmpty)
    assert(searchResultEntry.attributes("objectClass").contains("top"))
    assert(searchResultEntry.attributes("objectClass").contains("ScalaLDAProotDSE"))

    assert(searchResultEntry.attributes("structuralObjectClass").nonEmpty)
    assert(searchResultEntry.attributes("structuralObjectClass").head.nonEmpty)
    assert(searchResultEntry.attributes("structuralObjectClass").head === "ScalaLDAProotDSE")

    assert(searchResultEntry.attributes("configContext").nonEmpty)
    assert(searchResultEntry.attributes("configContext").head.nonEmpty)
    assert(searchResultEntry.attributes("configContext").head === "cn=config")

    assert(searchResultEntry.attributes.get("monitorContext").nonEmpty)
    assert(searchResultEntry.attributes("monitorContext").head.nonEmpty)
    assert(searchResultEntry.attributes("monitorContext").head === "cn=Monitor")

    assert(searchResultEntry.attributes("namingContexts").nonEmpty)
    assert(searchResultEntry.attributes("namingContexts").head.nonEmpty)
    assert(searchResultEntry.attributes("namingContexts").head === "dc=example,dc=com")

    assert(searchResultEntry.attributes.get("supportedControl").nonEmpty)
    //assert(searchResultEntry.attributes("supportedControl").head.nonEmpty) //There is 8 on a bare bones openldap

    assert(searchResultEntry.attributes.get("supportedExtension").nonEmpty)
    //assert(searchResultEntry.attributes("supportedExtension").head.nonEmpty) //There is 4 on a bare bones openldap

    assert(searchResultEntry.attributes.get("supportedFeatures").nonEmpty)
    //assert(searchResultEntry.attributes("supportedFeatures").head.nonEmpty) //There's 6 on a bare bones openldap

    assert(searchResultEntry.attributes("supportedLDAPVersion").nonEmpty)
    assert(searchResultEntry.attributes("supportedLDAPVersion").head.nonEmpty)
    assert(searchResultEntry.attributes("supportedLDAPVersion").head === "3")

    assert(searchResultEntry.attributes.get("entryDN").nonEmpty)

    assert(searchResultEntry.attributes("subschemaSubentry").nonEmpty)
    assert(searchResultEntry.attributes("subschemaSubentry").head.nonEmpty)
    assert(searchResultEntry.attributes("subschemaSubentry").head === "cn=Subschema")

    //openldap does not return these, though I think it should
    assert(searchResultEntry.attributes("supportedSASLMechanisms").nonEmpty)
    assert(searchResultEntry.attributes("supportedSASLMechanisms").head.nonEmpty)
    assert(searchResultEntry.attributes("vendorName").nonEmpty)
    assert(searchResultEntry.attributes("vendorName").head.nonEmpty)
    assert(searchResultEntry.attributes("vendorVersion").nonEmpty)
    assert(searchResultEntry.attributes("vendorVersion").head.nonEmpty)
    assert(searchResultEntry.attributes("creatorsName").nonEmpty)
    assert(searchResultEntry.attributes("creatorsName").head.nonEmpty)
    assert(searchResultEntry.attributes("createTimestamp").nonEmpty)
    assert(searchResultEntry.attributes("createTimestamp").head.nonEmpty)
    assert(searchResultEntry.attributes("modifiersName").nonEmpty)
    assert(searchResultEntry.attributes("modifiersName").head.nonEmpty)
    assert(searchResultEntry.attributes("modifyTimestamp").nonEmpty)
    assert(searchResultEntry.attributes("modifyTimestamp").head.nonEmpty)

    println(response)
  }

}
