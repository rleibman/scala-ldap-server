package ldap.rfc3062

import ldap.Config

trait PasswordPolicy {
  val generatePasswordIfEmpty: Boolean = true
  def validatePassword(oldPassword: String, newPassword: String): List[String]
}

//TODO get parameters from config
case object SimplePasswordPolicy extends PasswordPolicy with Config {
  override def validatePassword(oldPassword: String,
                                newPassword: String): List[String] = {
    List.empty
  }
}
