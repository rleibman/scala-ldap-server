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

import java.net.URI
import java.util.UUID
import buildinfo.BuildInfo

case class LDAPResultType(code: Int)

object LDAPResultType {
  val success = LDAPResultType(0)
  val operationsError = LDAPResultType(1)
  val protocolError = LDAPResultType(2)
  val timeLimitExceeded = LDAPResultType(3)
  val sizeLimitExceeded = LDAPResultType(4)
  val compareFalse = LDAPResultType(5)
  val compareTrue = LDAPResultType(6)
  val authMethodNotSupported = LDAPResultType(7)
  val strongerAuthRequired = LDAPResultType(8)
  //                       -- 9 reserved --
  val referral = LDAPResultType(10)
  val adminLimitExceeded = LDAPResultType(11)
  val unavailableCriticalExtension = LDAPResultType(12)
  val confidentialityRequired = LDAPResultType(13)
  val saslBindInProgress = LDAPResultType(14)
  val noSuchAttribute = LDAPResultType(16)
  val undefinedAttributeType = LDAPResultType(17)
  val inappropriateMatching = LDAPResultType(18)
  val constraintViolation = LDAPResultType(19)
  val attributeOrValueExists = LDAPResultType(20)
  val invalidAttributeSyntax = LDAPResultType(21)
  //                       -- 22-31 unused --
  val noSuchObject = LDAPResultType(32)
  val aliasProblem = LDAPResultType(33)
  val invalidDNSyntax = LDAPResultType(34)
  //                       -- 35 reserved for undefined isLeaf --
  val aliasDereferencingProblem = LDAPResultType(36)
  //                       -- 37-47 unused --
  val inappropriateAuthentication = LDAPResultType(48)
  val invalidCredentials = LDAPResultType(49)
  val insufficientAccessRights = LDAPResultType(50)
  val busy = LDAPResultType(51)
  val unavailable = LDAPResultType(52)
  val unwillingToPerform = LDAPResultType(53)
  val loopDetect = LDAPResultType(54)
  //                       -- 55-63 unused --
  val namingViolation = LDAPResultType(64)
  val objectClassViolation = LDAPResultType(65)
  val notAllowedOnNonLeaf = LDAPResultType(66)
  val notAllowedOnRDN = LDAPResultType(67)
  val entryAlreadyExists = LDAPResultType(68)
  val objectClassModsProhibited = LDAPResultType(69)
  //                       -- 70 reserved for CLDAP --
  val affectsMultipleDSAs = LDAPResultType(71)
  //                       -- 72-79 unused --
  val other = LDAPResultType(80)
}

trait MessageProtocolOp
sealed trait LdapAuthentication
case class LdapSimpleAuthentication(password: String) extends LdapAuthentication
case class LdapSaslAuthentication(mechanism: String,
                                  credentials: Option[String] = None)
    extends LdapAuthentication
case class LdapResult(opResult: LDAPResultType,
                      matchedDN: String,
                      diagnosticMessage: String,
                      referral: List[URI] = List())

object SearchRequestScope extends Enumeration {
  type SearchRequestScope = Value
  val baseObject, singleLevel, wholeSubtree, children = Value
}
import SearchRequestScope._
object DerefAliases extends Enumeration {
  type DerefAliases = Value
  val neverDerefAliases, derefInSearching, derefiFindingBaseObj, derefAlways =
    Value
}
import DerefAliases._

case class FilterType(value: Int)

object FilterType {
  val and = 0
  val or = 1
  val not = 2
  val equalityMatch = 3
  val substrings = 4
  val greaterOrEqual = 5
  val lessOrEqual = 6
  val present = 7
  val approxMatch = 8
  val extensibleMatch = 9
}

sealed abstract class Filter(val filterType: Int)
case class AndFilter(filters: Filter*) extends Filter(FilterType.and)
case class OrFilter(filters: Filter*) extends Filter(FilterType.or)
case class NotFilter(filter: Filter) extends Filter(FilterType.not)
case class EqualityMatchFilter(attributeDescription: String,
                               attributeValue: String)
    extends Filter(FilterType.equalityMatch)
object SubstringValueType extends Enumeration {
  type SubstringValueType = Value
  val initial, any, `final` = Value
}
import SubstringValueType._
import java.time.format.DateTimeFormatter

case class SubstringValue(substringValueType: SubstringValueType,
                          substring: String)
case class SubstringsFilter(`type`: String, substrings: Seq[SubstringValue])
    extends Filter(FilterType.substrings)
case class GreaterOrEqualFilter(attributeDescription: String,
                                attributeValue: String)
    extends Filter(FilterType.greaterOrEqual)
case class LessOrEqualFilter(attributeDescription: String,
                             attributeValue: String)
    extends Filter(FilterType.lessOrEqual)
case class PresentFilter(str: String) extends Filter(FilterType.present)
case class AproxMatchFilter(attributeDescription: String,
                            attributeValue: String)
    extends Filter(FilterType.approxMatch)
case class ExtensibleMatchFilter(matchingRuleId: Option[String],
                                 attributeDescription: Option[String],
                                 assertionValue: String,
                                 dnAttributes: Boolean = false)
    extends Filter(FilterType.equalityMatch)

trait Request extends MessageProtocolOp
trait Response extends MessageProtocolOp

sealed trait SearchResult extends Response
case class SearchResultEntry(uuid: UUID,
                             dn: String,
                             attributes: Map[String, Seq[String]])
    extends SearchResult
case class SearchResultDone(ldapResult: LdapResult) extends SearchResult
case class SearchResultEntryReference() extends SearchResult

case class UnbindRequest() extends Request
case class AbandonRequest(messageId: Long) extends Request
case class BindRequest(version: Int,
                       name: String,
                       authChoice: LdapAuthentication)
    extends Request
case class BindResponse(ldapResult: LdapResult,
                        serverSaslCreds: Option[String] = None)
    extends Response
abstract class IntermediateRespose() extends Response {
  val oid: Option[LDAPOID]
}

case class SearchRequest(
    baseObject: String,
    scope: SearchRequestScope = SearchRequestScope.singleLevel,
    derefAliases: DerefAliases = DerefAliases.derefAlways,
    sizeLimit: Int = 0,
    timeLimit: Int = 0,
    typesOnly: Boolean = false,
    filter: Option[Filter] = None,
    attributes: Seq[String] = Seq.empty
) extends Request

case class SearchResultReference(str: String) extends Response

case object ChangeType extends Enumeration {
  type ChangeType = Value
  val add, delete, replace = Value
}
import ChangeType._
case class Change(changeType: ChangeType,
                  attributeDescription: String,
                  values: List[String])
case class ModifyRequest(dn: String, changes: List[Change]) extends Request
case class ModifyResponse(ldapResult: LdapResult) extends Response
case class AddRequest(dn: String, userAttributes: Map[String, Seq[String]])
    extends Request
case class AddResponse(ldapResult: LdapResult) extends Response
case class DelRequest(dn: String) extends Request
case class DelResponse(ldapResult: LdapResult) extends Response
case class ModifyDNRequest(dn: String,
                           newDN: String,
                           deleteOld: Boolean,
                           newSuperiorDN: Option[String] = None)
    extends Request
case class ModifyDNResponse(ldapResult: LdapResult) extends Response
case class CompareRequest(dn: String,
                          attributeDescription: String,
                          attributeValue: String)
    extends Request
case class CompareResponse(ldapResult: LdapResult) extends Response

trait ExtendedRequest extends Request {
  def oid: LDAPOID
}

trait ExtendedResponse extends Response {
  def ldapResult: LdapResult
  def oid: Option[LDAPOID] = None
}

case class NoticeOfDisconnection(ldapResult: LdapResult)
    extends ExtendedResponse {
  override val oid = Some(LDAPOID("1.3.6.1.4.1.1466.20036"))
}

case class LDAPOID(value: String)

case class SupportedControl(oid: LDAPOID, name: String)
case class SupportedExtension(oid: LDAPOID, name: String)
case class SupportedFeature(oid: LDAPOID, name: String)

trait Control {
  val controlType: SupportedControl
  val criticality: Boolean = false
}

case class LdapMessage(messageId: Long,
                       protocolOp: MessageProtocolOp,
                       controls: Seq[Control] = Seq.empty)

object Node {
  def operationAttributes = Set(
    "entryUUID",
    "creatorsName",
    "createTimestamp",
    "modifiersName",
    "modifyTimestamp",
    "structuralObjectClass",
    "governingStructureRule",
    "objectClass",
    "attributeTypes",
    "matchingRules",
    "distinguishedNameMatch",
    "ldapSyntaxes",
    "matchingRuleUse"
  )
  def filterOutOperationalAttributes(attributes: Map[String, Seq[String]]) = {
    attributes.filter(a => !operationAttributes.contains(a._1))
  }
  def apply(
      id: String,
      dn: String,
      userAttributes: Map[String, Seq[String]],
      parentId: Option[String],
      baseDN: String,
      structuralObjectClass: String = "subentry",
      objectClass: List[String] = List.empty[String]
  ): Node = {
    val date = java.time.ZonedDateTime
      .now()
      .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssZ"))
    UserNode(
      id = id,
      dn = dn,
      userAttributes = filterOutOperationalAttributes(userAttributes),
      parentId = parentId,
      creatorsName = s"cn=Manager,${baseDN}",
      createTimeStamp = date,
      modifiersName = s"cn=Manager,${baseDN}",
      modifyTimestamp = date,
      structuralObjectClass = structuralObjectClass,
      governingStructureRule = "",
      objectClass = objectClass,
      attributeTypes = List.empty[String],
      matchingRules = List.empty[String],
      distinguishedNameMatch = List.empty[String],
      ldapSyntaxes = List.empty[String],
      matchingRuleUse = List.empty[String],
      subschemaSubentry = "cn=Subschema"
    )
  }
}

sealed trait Node {
  def id: String
  def dn: String
  def userAttributes: Map[String, Seq[String]]
  def creatorsName: String
  def createTimeStamp: String
  def modifiersName: String
  def modifyTimestamp: String
  def structuralObjectClass: String
  def objectClass: List[String]
  def subschemaSubentry: String
  def operationalAttributes: Map[String, Seq[String]]
}

case class UserNode(
    id: String,
    dn: String,
    userAttributes: Map[String, Seq[String]],
    parentId: Option[String],
    //Operational Attributes, per rfc4512
    creatorsName: String,
    createTimeStamp: String,
    modifiersName: String,
    modifyTimestamp: String,
    structuralObjectClass: String,
    governingStructureRule: String,
    objectClass: List[String],
    attributeTypes: List[String],
    matchingRules: List[String],
    distinguishedNameMatch: List[String],
    ldapSyntaxes: List[String],
    matchingRuleUse: List[String],
    subschemaSubentry: String
) extends Node {
  override val operationalAttributes: Map[String, Seq[String]] = Map(
    "creatorsName" -> Seq(creatorsName),
    "createTimestamp" -> Seq(createTimeStamp),
    "modifiersName" -> Seq(modifiersName),
    "modifyTimestamp" -> Seq(modifyTimestamp),
    "structuralObjectClass" -> Seq(structuralObjectClass),
    "governingStructureRule" -> Seq(governingStructureRule),
    "objectClass" -> objectClass,
    "attributeTypes" -> attributeTypes,
    "matchingRules" -> matchingRules,
    "distinguishedNameMatch" -> distinguishedNameMatch,
    "ldapSyntaxes" -> ldapSyntaxes,
    "matchingRuleUse" -> matchingRuleUse,
    "subschemaSubentry" -> Seq(subschemaSubentry)
  )
}

trait ServerStructuralNode extends Node with Config {
  override val creatorsName = "roberto@leibman.net"
  override val createTimeStamp = BuildInfo.builtAtString
  override val modifiersName = "roberto@leibman.net"
  override val modifyTimestamp = BuildInfo.builtAtString
  override val subschemaSubentry = "cn=Subschema"
  override val structuralObjectClass = "subentry"
  override lazy val operationalAttributes: Map[String, Seq[String]] = Map(
    "creatorsName" -> Seq(creatorsName),
    "createTimestamp" -> Seq(createTimeStamp),
    "modifiersName" -> Seq(modifiersName),
    "modifyTimestamp" -> Seq(modifyTimestamp),
    "structuralObjectClass" -> Seq(structuralObjectClass),
    "objectClass" -> objectClass,
    "subschemaSubentry" -> Seq(subschemaSubentry)
  )
}

case object RootNode extends ServerStructuralNode {
  val supportedControls = List(
    SupportedControl(
      LDAPOID("2.16.840.1.113730.3.4.18"),
      "Proxied Authorization v2 Request Control"), //  TODO (RFC 4370)
    SupportedControl(LDAPOID("2.16.840.1.113730.3.4.2"),
                     "ManageDsaIT Request Control"), //  TODO (RFC 3296)
    SupportedControl(LDAPOID("1.3.6.1.4.1.4203.1.10.1"), "Subentries"), //  TODO (RFC 3672)
    SupportedControl(LDAPOID("1.2.840.113556.1.4.319"),
                     "Simple Paged Results Control"), //  TODO (RFC 2696)
    SupportedControl(LDAPOID("1.2.826.0.1.3344810.2.3"),
                     "Matched Values Request Control"), //  TODO (RFC 3876)
    SupportedControl(
      LDAPOID("1.3.6.1.1.13.2"),
      "Post-Read Request and Response Controls"), //  TODO (RFC 4527)
    SupportedControl(
      LDAPOID("1.3.6.1.1.13.1"),
      "Pre-Read Request and Response Controls"), //  TODO (RFC 4527)
    SupportedControl(LDAPOID("1.3.6.1.1.12"), "Assertion Request Control"), //  TODO (RFC 4528)
    SupportedControl(LDAPOID("1.3.6.1.4.1.1466.20037"), "StartTLS Request") //  TODO (RFC 4511)
  )
  val supportedExtensions = List(
    SupportedExtension(LDAPOID("1.3.6.1.4.1.4203.1.11.3"),
                       "\"Who Am I?\" Request"), //  TODO (RFC 4532)
    SupportedExtension(LDAPOID("1.3.6.1.1.8"), "Cancel Request") //  TODO (RFC 3909)
  )
  val supportedFeatures = List(
    SupportedFeature(LDAPOID("1.3.6.1.1.14"), "Modify-Increment."), //  TODO (RFC 4525)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.1"),
                     "All Operational Attributes."), //  TODO (RFC 3673)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.2"), "OC AD Lists"), //  TODO (RFC 4529)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.3"), "True/False Filters"), //  TODO (RFC 4526)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.4"),
                     "Language tags options"), //  TODO (RFC 3866)
    SupportedFeature(LDAPOID("1.3.6.1.4.1.4203.1.5.5"),
                     "Language range options") //  TODO (RFC 3866)
  )
  override val id = "821f6b66-9ac7-487e-9dcc-db78d6aab654"
  override val dn = ""
  override val structuralObjectClass = "ScalaLDAProotDSE"
  override val objectClass = List("top", "ScalaLDAProotDSE")
  override val userAttributes = Map(
    "objectClass" -> objectClass,
    "vendorName" -> List("scala-ldap-server"),
    "vendorVersion" -> List(buildinfo.BuildInfo.version),
    "configContext" -> List("cn=config"),
    "monitorContext" -> List("cn=Monitor"),
    "subschemaSubentry" -> List(subschemaSubentry),
    "namingContexts" -> List(BaseNode.dn),
    "supportedControl" -> (supportedControls ++ plugins.flatMap(
      _.supportedControls))
      .map(_.oid.value), //TODO this is a dynamic value, should it be saved? calculated? calculated AND saved? saved when a new plugin is instnalled?
    "supportedExtension" -> (supportedExtensions ++ plugins.flatMap(
      _.supportedExtensions))
      .map(_.oid.value), //TODO this is a dynamic value, should it be saved? calculated? calculated AND saved? saved when a new plugin is instnalled?
    "supportedFeature" -> (supportedFeatures ++ plugins.flatMap(
      _.supportedFeatures))
      .map(_.oid.value), //TODO this is a dynamic value, should it be saved? calculated? calculated AND saved? saved when a new plugin is instnalled?
    "supportedLDAPVersion" -> List("3"),
    "supportedSASLMechanisms" -> List("LOGIN", "PLAIN"),
    "altServer" -> List(),
    "entryDN" -> List("")
  )
}

case object BaseNode extends ServerStructuralNode {
  override val id = "dba866a2-29ee-4c1c-9897-021835004040"
  override val dn = baseDN
  override val objectClass = List("top", "dcObject", "organization")
  override val userAttributes = Map(
    "dc" -> List("example"),
    "o" -> List("example"),
    "ou" -> List("example"),
    "description" -> List("example")
  )
}
