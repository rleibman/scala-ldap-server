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
case class LdapSaslAuthentication(mechanism: String, credentials: Option[String] = None) extends LdapAuthentication
case class LdapResult(opResult: LDAPResultType, matchedDN: String, diagnosticMessage: String, referral: List[URI] = List())

object SearchRequestScope extends Enumeration {
  type SearchRequestScope = Value
  val baseObject, singleLevel, wholeSubtree, children = Value
}
import SearchRequestScope._
object DerefAliases extends Enumeration {
  type DerefAliases = Value
  val neverDerefAliases, derefInSearching, derefiFindingBaseObj, derefAlways = Value
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
case class EqualityMatchFilter(attributeDescription: String, attributeValue: String) extends Filter(FilterType.equalityMatch)
object SubstringValueType extends Enumeration {
  type SubstringValueType = Value
  val initial, any, `final` = Value
}
import SubstringValueType._
import java.time.format.DateTimeFormatter

case class SubstringValue(substringValueType: SubstringValueType, substring: String)
case class SubstringsFilter(`type`: String, substrings: Seq[SubstringValue]) extends Filter(FilterType.substrings)
case class GreaterOrEqualFilter(attributeDescription: String, attributeValue: String) extends Filter(FilterType.greaterOrEqual)
case class LessOrEqualFilter(attributeDescription: String, attributeValue: String) extends Filter(FilterType.lessOrEqual)
case class PresentFilter(str: String) extends Filter(FilterType.present)
case class AproxMatchFilter(attributeDescription: String, attributeValue: String) extends Filter(FilterType.approxMatch)
case class ExtensibleMatchFilter(matchingRuleId: Option[String], attributeDescription: Option[String], assertionValue: String, dnAttributes: Boolean = false) extends Filter(FilterType.equalityMatch)

trait Request extends MessageProtocolOp
trait Response extends MessageProtocolOp

sealed trait SearchResult extends Response
case class SearchResultEntry(uuid: UUID, dn: String, attributes: Map[String, Seq[String]]) extends SearchResult
case class SearchResultDone(ldapResult: LdapResult) extends SearchResult
case class SearchResultEntryReference() extends SearchResult

case class UnbindRequest() extends Request
case class AbandonRequest(messageId: Long) extends Request
case class BindRequest(version: Int, name: String, authChoice: LdapAuthentication) extends Request
case class BindResponse(ldapResult: LdapResult, serverSaslCreds: Option[String] = None) extends Response
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
case class Change(changeType: ChangeType, attributeDescription: String, values: List[String])
case class ModifyRequest(dn: String, changes: List[Change]) extends Request
case class ModifyResponse(ldapResult: LdapResult) extends Response
case class AddRequest(dn: String, userAttributes: Map[String, Seq[String]]) extends Request
case class AddResponse(ldapResult: LdapResult) extends Response
case class DelRequest(dn: String) extends Request
case class DelResponse(ldapResult: LdapResult) extends Response
case class ModifyDNRequest(dn: String, newDN: String, deleteOld: Boolean, newSuperiorDN: Option[String] = None) extends Request
case class ModifyDNResponse(ldapResult: LdapResult) extends Response
case class CompareRequest(dn: String, attributeDescription: String, attributeValue: String) extends Request
case class CompareResponse(ldapResult: LdapResult) extends Response

case class LDAPOID(value: String)

case class SupportedControl(oid: LDAPOID, name: String)
case class SupportedExtension(oid: LDAPOID, name: String)
case class SupportedFeature(oid: LDAPOID, name: String)

trait Control {
  val controlType: SupportedControl
  val criticality: Boolean = false
}

case class LdapMessage(messageId: Long, protocolOp: MessageProtocolOp, controls: Seq[Control] = Seq.empty)

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
    val date = java.time.ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssZ"))
    apply(
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

case class Node(
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
) {
  def operationalAttributes: Map[String, Seq[String]] = {
    Map(
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
}

object AttributeTypeUsage extends Enumeration {
  type AttributeTypeUsage = Value
  val userApplications, directoryOperation, distributedOperation, dSAOperation = Value
}

import AttributeTypeUsage._

case class AttributeType(
    oid: LDAPOID,
    names: List[String],
    description: String,
    syntax: Option[LDAPOID],
    usage: Option[AttributeTypeUsage] = None,
    isSingleValue: Boolean = false,
    isCollective: Boolean = true,
    isUserModifiable: Boolean = true,
    isOperational: Boolean = false,
    supertype: Option[String] = None,
    substringMatching: Option[String] = None,
    ordering: Option[String] = None,
    equality: Option[String] = None,
    isObsolete: Boolean = false
) {
  override def toString() = {
    s"""
( 
${oid} 
NAME ( '${names.mkString(" ")}' ) 
DESC '${description}' 
${if (isObsolete) "OBSOLETE" else ""} 
${supertype.fold("")(a => s"SUP ${a}")}
${equality.fold("")(a => s"EQUALITY ${a}")}
${ordering.fold("")(a => s"ORDERING ${a}")}
${substringMatching.fold("")(a => s"SUBSTR ${a}")}
${syntax.fold("")(a => s"SYNTAX ${a.toString}")}
${if (isSingleValue) "SINGLE-VALUE" else ""}
${if (isCollective) "COLLECTIVE" else ""}
${if (isUserModifiable) "" else "NO-USER-MODIFICATION"}
${usage.fold("")(a => s"USAGE ${a.toString}")}
)"""
  }.replaceAll("{\n }+", " ")
}

object ObjectClassType extends Enumeration {
  type ObjectClassType = Value
  val ABSTRACT, STRUCTURAL, AUXILIARY = Value
}

import ObjectClassType._

case class ObjectClass(
    oid: LDAPOID,
    names: List[String],
    description: String,
    objectClassType: Option[ObjectClassType] = None,
    superclasses: List[String] = List.empty,
    mandatory: List[String] = List.empty,
    optional: List[String] = List.empty,
    isObsolete: Boolean = false
) {
  override def toString() = {
    s"""
(
${oid} 
NAME ( '${names.mkString(" $ ")}' ) 
DESC '${description}' 
${if (isObsolete) "OBSOLETE" else ""}
${if (superclasses.isEmpty) "" else s"SUP ( ${superclasses.mkString(" $ ")} )"}
${objectClassType.fold("")(a => s"${a}")}
${if (optional.isEmpty) "" else s"MAY ( ${optional.mkString(" $ ")} )"}
${if (mandatory.isEmpty) "" else s"MUST ( ${mandatory.mkString(" $ ")} )"}
)
""".replaceAll("{\n }+", " ")
  }
}
