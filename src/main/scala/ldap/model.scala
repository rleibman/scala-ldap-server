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

case class LDAPResultType(code: Short)

object LDAPResultType {
  val success = new LDAPResultType(0)
  val operationsError = new LDAPResultType(1)
  val protocolError = new LDAPResultType(2)
  val timeLimitExceeded = new LDAPResultType(3)
  val sizeLimitExceeded = new LDAPResultType(4)
  val compareFalse = new LDAPResultType(5)
  val compareTrue = new LDAPResultType(6)
  val authMethodNotSupported = new LDAPResultType(7)
  val strongerAuthRequired = new LDAPResultType(8)
  //                       -- 9 reserved --
  val referral = new LDAPResultType(10)
  val adminLimitExceeded = new LDAPResultType(11)
  val unavailableCriticalExtension = new LDAPResultType(12)
  val confidentialityRequired = new LDAPResultType(13)
  val saslBindInProgress = new LDAPResultType(14)
  val noSuchAttribute = new LDAPResultType(16)
  val undefinedAttributeType = new LDAPResultType(17)
  val inappropriateMatching = new LDAPResultType(18)
  val constraintViolation = new LDAPResultType(19)
  val attributeOrValueExists = new LDAPResultType(20)
  val invalidAttributeSyntax = new LDAPResultType(21)
  //                       -- 22-31 unused --
  val noSuchObject = new LDAPResultType(32)
  val aliasProblem = new LDAPResultType(33)
  val invalidDNSyntax = new LDAPResultType(34)
  //                       -- 35 reserved for undefined isLeaf --
  val aliasDereferencingProblem = new LDAPResultType(36)
  //                       -- 37-47 unused --
  val inappropriateAuthentication = new LDAPResultType(48)
  val invalidCredentials = new LDAPResultType(49)
  val insufficientAccessRights = new LDAPResultType(50)
  val busy = new LDAPResultType(51)
  val unavailable = new LDAPResultType(52)
  val unwillingToPerform = new LDAPResultType(53)
  val loopDetect = new LDAPResultType(54)
  //                       -- 55-63 unused --
  val namingViolation = new LDAPResultType(64)
  val objectClassViolation = new LDAPResultType(65)
  val notAllowedOnNonLeaf = new LDAPResultType(66)
  val notAllowedOnRDN = new LDAPResultType(67)
  val entryAlreadyExists = new LDAPResultType(68)
  val objectClassModsProhibited = new LDAPResultType(69)
  //                       -- 70 reserved for CLDAP --
  val affectsMultipleDSAs = new LDAPResultType(71)
  //                       -- 72-79 unused --
  val other = new LDAPResultType(80)
}
import LDAPResultType._

trait MessageProtocolOp
sealed trait LdapAuthentication
case class LdapSimpleAuthentication(password: String) extends LdapAuthentication
case class LdapSaslAuthentication(mechanism: String, credentials: Option[String] = None) extends LdapAuthentication
case class LdapResult(opResult: LDAPResultType, matchedDN: String, diagnosticMessage: String, referral: List[URI] = List())

object SearchRequestScope extends Enumeration {
  type SearchRequestScope = Value
  val baseObject, singleLevel, wholeSubtree = Value
}
import SearchRequestScope._
object DerefAliases extends Enumeration {
  type DerefAliases = Value
  val neverDerefAliases, derefInSearching, derefiFindingBaseObj, derefAlways = Value
}
import DerefAliases._
sealed trait Filter

case class StringFilter(str: String) extends Filter

trait Request extends MessageProtocolOp
trait Response extends MessageProtocolOp

sealed trait SearchResult extends Response
case class SearchResultEntry(uuid: UUID, dn: String, attributes: Map[String, Seq[String]]) extends SearchResult
case class SearchResultDone(ldapResult: LdapResult) extends SearchResult
case class SearchResultEntryReference() extends SearchResult

case class UnbindRequest() extends Request
case class AbandonRequest(messageId: Long) extends Request
case class BindRequest(version: Byte, name: String, authChoice: LdapAuthentication) extends Request
case class BindResponse(ldapResult: LdapResult, serverSaslCreds: Option[String] = None) extends Response
abstract class IntermediateRespose() extends Response {
  val oid: Option[LDAPOID]
}

case class SearchRequest(
  baseObject: String,
  scope: SearchRequestScope,
  derefAliases: DerefAliases,
  sizeLimit: Int,
  timeLimit: Int,
  typesOnly: Boolean,
  filter: Option[Filter] = None,
  attributes: Seq[String] = Seq()
) extends Request

case class SearchResultReference(str: String) extends Response
case class ModifyRequest(str: String) extends Request
case class ModifyResponse(str: String) extends Response
case class AddRequest(str: String) extends Request
case class AddResponse(str: String) extends Response
case class DelRequest(str: String) extends Request
case class DelResponse(str: String) extends Response
case class ModifyDNRequest(str: String) extends Request
case class ModifyDNResponse(str: String) extends Response
case class CompareRequest(str: String) extends Request
case class CompareResponse(str: String) extends Response

case class LDAPOID(value: String)

case class SupportedControl(oid: LDAPOID, name: String)

trait Control {
  val controlType: SupportedControl
  val criticality: Boolean = false
}

case class LdapMessage(messageId: Long, protocolOp: MessageProtocolOp, controls: Seq[Control] = Seq.empty)

case class Node(
  id: String,
  dn: String,
  operationalAttributes: Map[String, Seq[String]], ////rfc4512: Attributes. such as creatorsName, createTimestamp, modifiersName, modifyTimestamp, structuralObjectClass, governingStructureRule, objectClasses, attributeTypes, matchingRules, distinguishedNameMatch, ldapSyntaxes, matchingRuleUse
  userAttributes: Map[String, Seq[String]],
  parentId: Option[String],
  children: Seq[String] = Seq()
)

