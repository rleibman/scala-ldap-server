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

object LDAPResultType extends Enumeration {
  type LDAPResultType = Value
  val success, operationsError, protocolError, timeLimitExceeded, sizeLimitExceeded, compareFalse, compareTrue, authMethodNotSupported, strongerAuthRequired, reserved1, referral, adminLimitExceeded, unavailableCriticalExtension, confidentialityRequired, saslBindInProgress, noSuchAttribute, undefinedAttributeType, inappropriateMatching, constraintViolation, attributeOrValueExists, invalidAttributeSyntax = Value
}
import LDAPResultType._

trait MessageProtocolOp
trait LdapAuthentication
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
trait Filter

case class StringFilter(str: String) extends Filter
case class AttributeSelection()

trait SearchResult extends MessageProtocolOp
case class SearchResultEntry(dn: String, attributes: Map[String, Seq[String]]) extends SearchResult
case class SearchResultDone(ldapResult: LdapResult) extends MessageProtocolOp
case class SearchResultEntryReference() extends SearchResult

case class UnbindRequest() extends MessageProtocolOp
case class BindRequest(version: Byte, name: String, authChoice: LdapAuthentication) extends MessageProtocolOp
case class BindResponse(ldapResult: LdapResult, serverSaslCreds: Option[String] = None) extends MessageProtocolOp
case class SearchRequest(baseObject: String, scope: SearchRequestScope, derefAliases: DerefAliases, sizeLimit: Int, timeLimit: Int, typesOnly: Boolean, filter: Option[Filter] = None, attributes: Option[AttributeSelection] = None) extends MessageProtocolOp

case class LdapMessage(messageId: Long, protocolOp: MessageProtocolOp)

//Used internally to represent the attributes
case class Node(id: String, dn: String, attributes: Map[String, Seq[String]], parentId: Option[String], children: Seq[String])
