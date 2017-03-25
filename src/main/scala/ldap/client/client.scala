package ldap.client

import scala.collection.JavaConverters._
import javax.naming.ldap.InitialLdapContext
import java.util.Hashtable
import javax.naming.{ Context, NamingException, NamingEnumeration }
import javax.naming.directory.{ SearchControls, SearchResult, Attribute }
import scala.concurrent.Future
import javax.naming.directory.SearchResult
import akka.actor.ActorSystem
import akka.event.Logging
import scala.concurrent.Promise

/**
 * The LdapAuthenticator faciliates user/password authentication against an LDAP server.
 * It delegates the application specific parts of the LDAP configuration to the given LdapAuthConfig instance,
 * which is also responsible for creating the object representing the application-specific user context.
 *
 * Authentication against an LDAP server is done in two separate steps:
 * First, some "search credentials" are used to log into the LDAP server and perform a search for the directory entry
 * matching a given user name. If exactly one user entry is found another LDAP bind operation is performed using the
 * principal DN of the found user entry to validate the password.
 */
trait LdapConfig[USER, ROLE] {
  def roleSearchFilter(t: USER, application: String): String
  def roleSearchBase(): String
  def configureRoleSearchControls(searchControls: SearchControls): SearchControls
  def createRoleObject(queryResult: LdapQueryResult): Option[ROLE]

  /**
   * The application-specific environment properties for the InitialLdapContext.
   * If the application uses 'simple' security authentication then the only required setting is the one configuring
   * the LDAP server and port:
   *
   * {{{javax.naming.Context.PROVIDER_URL -> "ldap://ldap.testathon.net:389"}}}
   *
   * However, you can set any of the properties defined in javax.naming.Context. (If a Context.SECURITY_PRINCIPAL
   * property is specified it overrides the one created by the `securityPrincipal` method).
   *
   * In addition to configuring the properties with this method the application can also choose to have this method
   * return a `Seq.empty` and configure all settings in a `jndi.properties` file on the classpath. A combination of
   * the two is also allowed.
   */
  def contextEnv(user: String, pass: String): Seq[(String, String)]

  /**
   * Returns the credentials used to bind to the LDAP server in order to search for a matching user entry.
   * For example:
   *
   * {{{val searchCredentials = "CN=stuart,OU=users,DC=testathon,DC=net" -> "stuart"}}}
   */
  def searchCredentials: (String, String)

  /**
   * The DN of the entity to base the directory search on.
   * For example:
   *
   * {{{def searchBase(user: String) = "OU=users,DC=testathon,DC=net"}}}
   */
  def searchBase(user: String): String

  /**
   * The search filter to use for searching for the user entry.
   * For example:
   *
   * {{{def searchFilter(user: String) = "(uid=%s)" format user}}}
   */
  def searchFilter(user: String): String

  /**
   * Configures the given searchControls instance according the application-specific requirements.
   * For example:
   *
   * {{{
   * searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
   * searchControls.setReturningAttributes(Array("givenName", "sn"))
   * }}}
   */
  def configureSearchControls(searchControls: SearchControls, user: String): Unit

  /**
   * Creates a user object from the given LDAP query result.
   * The method can also choose to return None, in which case authentication will fail.
   */
  def createUserObject(queryResult: LdapQueryResult): Option[USER]
}

case class LdapQueryResult(
  name: String,
  fullName: String,
  className: String,
  relative: Boolean,
  obj: AnyRef,
  attrs: Map[String, LdapAttribute])

case class LdapAttribute(
    id: String,
    ordered: Boolean,
    values: Seq[String]) {
  def value: String = values.headOption.getOrElse("")
}

case class UserPass(user: String, pass: String)

trait AuthenticatorAndAuthorizer[USER, ROLE] {
  def authenticate(userPassOption: Option[UserPass]): Future[Option[USER]]
  def canUse(user: USER, application: String): Boolean
}

trait AuthorizationAndAuthenticationProvider[USER, ROLE] {
  def authenticatorAndAuthorizer: AuthenticatorAndAuthorizer[USER, ROLE]
}

/**
 * The LdapAuthenticator faciliates user/password authentication against an LDAP server.
 * It delegates the application specific parts of the LDAP configuration to the given LdapConfig instance,
 * which is also responsible for creating the object representing the application-specific user context.
 *
 * Authentication against an LDAP server is done in two separate steps:
 * First, some "search credentials" are used to log into the LDAP server and perform a search for the directory entry
 * matching a given user name. If exactly one user entry is found another LDAP bind operation is performed using the
 * principal DN of the found user entry to validate the password.
 */
class LdapAuthenticator[USER, ROLE](ldapConfig: LdapConfig[USER, ROLE])(implicit val actorSystem: ActorSystem) extends AuthenticatorAndAuthorizer[USER, ROLE] {
  import actorSystem.dispatcher
  val log = Logging(actorSystem, getClass)

  override def canUse(user: USER, application: String): Boolean = {
    val creds = ldapConfig.searchCredentials
    ldapContext(creds._1, creds._2) match {
      case Right(context) ⇒
        val results = context.search(
          ldapConfig.roleSearchBase(),
          ldapConfig.roleSearchFilter(user, application),
          ldapConfig.configureRoleSearchControls(new SearchControls()))
        results.asScala.toList.nonEmpty
      case Left(ex) ⇒
        log.warning("Could not authenticate with search user '{}': {}", creds._1, ex)
        false
    }
  }

  def authenticate(userPassOption: Option[UserPass]): Future[Option[USER]] = {
    def auth3(entry: LdapQueryResult, pass: String) = {
      ldapContext(entry.fullName, pass) match {
        case Right(authContext) ⇒
          authContext.close()
          ldapConfig.createUserObject(entry)
        case Left(ex) ⇒
          log.info("Could not authenticate user '{}': {}", entry.fullName, ex)
          None
      }
    }

    def auth2(searchContext: InitialLdapContext, userPass: UserPass) = {
      val UserPass(user, pass) = userPass
      query(searchContext, user) match {
        case entry :: Nil ⇒ auth3(entry, pass)
        case Nil ⇒
          log.warning("User '{}' not found (search filter '{}' and search base '{}'", user, ldapConfig.searchFilter(user),
            ldapConfig.searchBase(user))
          None
        case entries: Any ⇒
          log.warning(
            "Expected exactly one search result for search filter '{}' and search base '{}', but got {}",
            ldapConfig.searchFilter(user), ldapConfig.searchBase(user), entries.size)
          None
      }
    }

    def auth1(userPass: UserPass) = {
      val (searchUser, searchPass) = ldapConfig.searchCredentials
      ldapContext(searchUser, searchPass) match {
        case Right(searchContext) ⇒
          val result = auth2(searchContext, userPass)
          searchContext.close()
          result
        case Left(ex) ⇒
          log.warning("Could not authenticate with search user '{}': {}", searchUser, ex)
          None
      }
    }

    userPassOption match {
      case Some(userPass) ⇒ Future(auth1(userPass))
      case None ⇒
        log.warning("LdapAuthenticator.apply called with empty userPass, authentication not possible")
        Promise.successful(None).future
    }
  }

  def ldapContext(user: String, pass: String): Either[Throwable, InitialLdapContext] = {
    scala.util.control.Exception.catching(classOf[NamingException]).either {
      val env = new Hashtable[AnyRef, AnyRef]
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
      env.put(Context.SECURITY_PRINCIPAL, user)
      env.put(Context.SECURITY_CREDENTIALS, pass)
      env.put(Context.SECURITY_AUTHENTICATION, "simple")
      for { (key, value) ← ldapConfig.contextEnv(user, pass) } env.put(key, value)
      new InitialLdapContext(env, null)
    }
  }

  def query(ldapContext: InitialLdapContext, user: String): List[LdapQueryResult] = {
    val results: NamingEnumeration[SearchResult] = ldapContext.search(
      ldapConfig.searchBase(user),
      ldapConfig.searchFilter(user),
      searchControls(user))
    results.asScala.toList.map(searchResult2LdapQueryResult)
  }

  def searchControls(user: String): SearchControls = {
    val searchControls = new SearchControls
    ldapConfig.configureSearchControls(searchControls, user)
    searchControls
  }

  def searchResult2LdapQueryResult(searchResult: SearchResult): LdapQueryResult = {
    import searchResult._
    LdapQueryResult(
      name = getName,
      fullName = getNameInNamespace,
      className = getClassName,
      relative = isRelative,
      obj = getObject,
      attrs = getAttributes.getAll.asScala.toSeq.map(a ⇒ a.getID -> attribute2LdapAttribute(a))(collection.breakOut))
  }

  def attribute2LdapAttribute(attr: Attribute): LdapAttribute = {
    LdapAttribute(
      id = attr.getID,
      ordered = attr.isOrdered,
      values = attr.getAll.asScala.toSeq.map(v ⇒ if (v != null) v.toString else ""))
  }
}

//class LdapContext(user: String, pass: String) {
//  val env = new Hashtable[AnyRef, AnyRef]
//  env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
//  env.put(Context.SECURITY_PRINCIPAL, user)
//  env.put(Context.SECURITY_CREDENTIALS, pass)
//  env.put(Context.SECURITY_AUTHENTICATION, "simple")
//  for { (key, value) ← ldapConfig.contextEnv(user, pass) } env.put(key, value)
//  val internalContext = new InitialLdapContext(env, null)
//}