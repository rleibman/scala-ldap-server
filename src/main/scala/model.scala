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
import java.net.URI

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
object DerefAliases extends Enumeration {
  type DerefAliases = Value
  val neverDerefAliases, derefInSearching, derefiFindingBaseObj, derefAlways = Value
}

trait Filter

case class StringFilter(str: String) extends Filter
case class AttributeSelection()

trait SearchResult extends MessageProtocolOp
case class SearchResultEntry() extends SearchResult
case class SearchResultEntryReference() extends SearchResult
import DerefAliases._
import SearchRequestScope._

case class BindRequest(version: Byte, name: String, authChoice: LdapAuthentication) extends MessageProtocolOp
case class BindResponse(ldapResult: LdapResult, serverSaslCreds: Option[String] = None) extends MessageProtocolOp
case class SearchRequest(baseObject: String, scope: SearchRequestScope, derefAliases: DerefAliases, sizeLimit: Int, timeLimit: Int, typesOnly: Boolean, filter: Option[Filter] = None, attributes: Option[AttributeSelection] = None) extends MessageProtocolOp

case class LdapMessage(messageId: Long, protocolOp: MessageProtocolOp)
