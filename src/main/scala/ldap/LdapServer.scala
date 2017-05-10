/*
 *   Copyright (C) 2016  Roberto Leibman
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

//TODO add session management, currently each operation is coming by itself, they need to be
class LdapListener extends Actor with Config {
  import context.system
  import akka.io.Tcp._

  val log = Logging(context.system, getClass)

  val host = config.getString("scala-ldap-server.host")
  val port = config.getInt("scala-ldap-server.port")
  IO(Tcp) ! Bind(self, new InetSocketAddress(host, port))

  def receive = {
    case _@ Bound(localAddress) ⇒
      log.info(s"bound to ${localAddress}")
    // do some logging or setup ...

    case CommandFailed(_: Bind) ⇒ context stop self

    case _@ Connected(remote, local) ⇒
      log.debug(s"Connected ${remote} to ${local}")
      val handler = context.actorOf(Props[LdapHandler])
      val connection = sender()
      connection ! Register(handler)
  }
}

object LdapServer extends App with Config {
  // Create the actor system
  implicit val system = ActorSystem("scala-ldap-server")
  import system.dispatcher
  val log = Logging(system, getClass)

  //TODO move these to different plugins as needed, else we have to implement them within the ldap server or ldap handler
  val supportedControls = List(
    SupportedControl(LDAPOID("2.16.840.1.113730.3.4.18"), "Proxied Authorization v2 Request Control"), //  TODO (RFC 4370)
    SupportedControl(LDAPOID("2.16.840.1.113730.3.4.2"), "ManageDsaIT Request Control"), //  TODO (RFC 3296)
    SupportedControl(LDAPOID("1.3.6.1.4.1.4203.1.10.1"), "Subentries"), //  TODO (RFC 3672)
    SupportedControl(LDAPOID("1.2.840.113556.1.4.319"), "Simple Paged Results Control"), //  TODO (RFC 2696)
    SupportedControl(LDAPOID("1.2.826.0.1.3344810.2.3"), "Matched Values Request Control"), //  TODO (RFC 3876)
    SupportedControl(LDAPOID("1.3.6.1.1.13.2"), "Post-Read Request and Response Controls"), //  TODO (RFC 4527)
    SupportedControl(LDAPOID("1.3.6.1.1.13.1"), "Pre-Read Request and Response Controls"), //  TODO (RFC 4527)
    SupportedControl(LDAPOID("1.3.6.1.1.12"), "Assertion Request Control"), //  TODO (RFC 4528)
    SupportedControl(LDAPOID("1.3.6.1.4.1.1466.20037"), "StartTLS Request") //  TODO (RFC 4511)
  )
  val supportedExtensions = List(
    SupportedExtension(LDAPOID("1.3.6.1.4.1.4203.1.11.1"), "Password ModifY Request"), //  TODO (RFC 3062)
    SupportedExtension(LDAPOID("1.3.6.1.4.1.4203.1.11.3"), "\"Who Am I?\" Request"), //  TODO (RFC 4532)
    SupportedExtension(LDAPOID("1.3.6.1.1.8"), "Cancel Request") //  TODO (RFC 3909)
  )
  val supportedFeatures = List(
    SupportedFeature(LDAPOID("1.3.6.1.1.14"), "Modify-Increment."), //  TODO (RFC 4525)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.1"), "All Operational Attributes."), //  TODO (RFC 3673)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.2"), "OC AD Lists"), //  TODO (RFC 4529)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.3"), "True/False Filters"), //  TODO (RFC 4526)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.4"), "Language tags options"), //  TODO (RFC 3866)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.5"), "Language range options") //  TODO (RFC 3866)
  )

  init()

  def init() = {

    val dao = new MongoDAO()
    val fut = for {
      root ← dao.getNode("")
      root2 ← if (root.isEmpty) {
        dao.update(Node(
          id = "",
          dn = "",
          structuralObjectClass = "ScalaLDAProotDSE",
          userAttributes = Map(
            "objectClass" -> List("top", "ScalaLDAProotDSE"),
            "vendorName" -> List("scala-ldap-server"),
            "vendorVersion" -> List(buildinfo.BuildInfo.version),
            "configContext" -> List("cn=config"),
            "monitorContext" -> List("cn=Monitor"),
            "subschemaSubentry" -> List("cn=Subschema"),
            "namingContexts" -> List(baseDN),
            "supportedControl" -> (supportedControls ++ plugins.flatMap(_.supportedControls)).map(_.oid.value), //TODO this is a dynamic value, should it be saved? calculated? calculated AND saved? saved when a new plugin is instnalled?
            "supportedExtension" -> (supportedExtensions ++ plugins.flatMap(_.supportedExtensions)).map(_.oid.value), //TODO this is a dynamic value, should it be saved? calculated? calculated AND saved? saved when a new plugin is instnalled?
            "supportedFeature" -> (supportedFeatures ++ plugins.flatMap(_.supportedFeatures)).map(_.oid.value), //TODO this is a dynamic value, should it be saved? calculated? calculated AND saved? saved when a new plugin is instnalled?
            "supportedLDAPVersion" -> List("3"),
            "supportedSASLMechanisms" -> List("LOGIN", "PLAIN"),
            "altServer" -> List(),
            "entryDN" -> List("")
          ),
          baseDN = baseDN,
          parentId = None
        ))
      } else {
        Future.successful(root.get)
      }
      base ← dao.getNode(baseDN)
      base2 ← if (base.isEmpty) {
        dao.update(Node(
          id = "",
          dn = baseDN,
          baseDN = baseDN,
          userAttributes = Map(
            "dc" -> List("example"),
            "o" -> List("example"),
            "ou" -> List("example"),
            "description" -> List("example")
          ),
          parentId = Some(root2.id),
          objectClass = List("top", "dcObject", "organization")
        ))
      } else {
        Future.successful(base.get)
      }
      subschema ← dao.getNode("cn=Subschema")
      subschema2 ← if (subschema.isEmpty) {
        //https://www.ldap.com/understanding-ldap-schema
        dao.update(Node(
          id = "",
          dn = "cn=Subschema",
          baseDN = baseDN,
          structuralObjectClass = "subentry",
          userAttributes = Map(
            "objectClass" -> List("top", "subentry", "subschema", "extensibleObject"),
            "cn" -> List("Subschema"),
            "description" -> List("example"),
            "ldapSyntaxes" -> List(),
            "matchingRules" -> List(
              "( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )"
            ),
            "attributeTypes" -> List(
              "( 2.5.21.5 NAME 'attributeTypes' DESC 'RFC4512: attribute types' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
              "( 2.5.21.6 NAME 'objectClasses' DESC 'RFC4512: object classes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )"
            ),
            "objectClasses" -> List(
              "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
              "( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( title $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l ) )"
            )
          ),
          parentId = Some(root2.id)
        ))
      } else {
        Future.successful(base.get)
      }
      firstLevel ← {
        val firstLevelNodes = List(
          Node(id = "", dn = s"cn=Manager,${baseDN}", baseDN = baseDN, structuralObjectClass = "organizationalRole", userAttributes = Map("objectClass" -> List("organizationalRole"), "cn" -> List("Manager"), "description" -> List("Directory Manager")), parentId = Some(base2.id)),
          Node(id = "", dn = s"ou=Groups,${baseDN}", baseDN = baseDN, structuralObjectClass = "organizationalUnit", userAttributes = Map("objectClass" -> List("organizationalUnit"), "ou" -> List("groups")), parentId = Some(base2.id)),
          Node(id = "", dn = s"ou=People,${baseDN}", baseDN = baseDN, structuralObjectClass = "organizationalUnit", userAttributes = Map("objectClass" -> List("organizationalUnit"), "ou" -> List("people")), parentId = Some(base2.id))
        )
        Future.sequence(firstLevelNodes.map { node ⇒
          for {
            gotNode ← dao.getNode(node.dn)
            updatedNode ← if (gotNode.isEmpty) { dao.update(node) } else { Future.successful(gotNode.get) }
          } yield (updatedNode)
        })
      }
      pluginInits <- Future.traverse(plugins)(_.initialize(config))
    } yield (root2)

    Await.result(fut, 5 minutes)
  }

  // Create the 'ldap' actor
  val ldap = system.actorOf(Props[LdapListener], "ldap")

  def shutdown() = {
    system.terminate()
  }
}
