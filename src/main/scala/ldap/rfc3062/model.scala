package ldap.rfc3062

import ldap._

case class ChangePasswordRequest(userIdentity: String, oldPassword: String, newPassword: String) extends ExtendedRequest {
  override val oid = RFC3062Plugin.oid
}
case class ChangePasswordResponse(ldapResult: LdapResult, generatedPassword: Option[String]) extends ExtendedResponse {

}