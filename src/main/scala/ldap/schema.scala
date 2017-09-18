/*
 * Copyright (C) 2017  Roberto Leibman
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ldap

import scala.util.matching.Regex
import better.files._

object AttributeTypeUsage extends Enumeration {
  type AttributeTypeUsage = Value
  val userApplications, directoryOperation, distributedOperation, dSAOperation =
    Value
}

//import
//Amazingly, someone else figured this out already, only in ruby :(
// https://github.com/inscitiv/ruby-ldapserver/blob/master/lib/ldap/server/syntax.rb
trait LdapRegex {
  val regex: Regex

  val keyStr                = s"[a-zA-Z][a-zA-Z0-9;-]*".r
  val numericOID            = s"(\\d[\\d.]+\\d)".r
  val wOID                  = s"\\s*(${keyStr}|\\d[\\d.]+\\d)\\s*".r
  private val _wOID         = s"\\s*(?:${keyStr}|\\d[\\d.]+\\d)\\s*".r
  val OIDs                  = s"(${_wOID}|\\s+\\(${_wOID}(?:\\$$${wOID})*\\)\\s*)".r
  private val _qDescription = s"\\s*'${keyStr}'\\s*".r
  val qDescriptions =
    s"(${_qDescription}|\\s*\\((?:${_qDescription})+\\)\\s*)".r
  val qDString = s"\\s*'(.*?)'\\s*".r
  val nOIDLen  = s"(\\d[\\d.]+\\d)(?:\\{(\\d+)\\})?".r
  val attributeUsage =
    s"(userApplications|directoryOperation|distributedOperation|dSAOperation)"
}

sealed trait LdapSyntaxResource

object LdapSyntax extends LdapRegex {
  override val regex =
    s"\\A\\s*\\(\\s*${numericOID}\\s*(?:DESC${qDString})?(?:X-BINARY-TRANSFER-REQUIRED\\s*'(TRUE|FALSE)'\\s*)?(?:X-NOT-HUMAN-READABLE\\s*'(TRUE|FALSE)'\\s*)?\\s*\\)\\s*\\z".r

  def apply(str: String): Option[LdapSyntax] =
    str match {
      case regex(oid, description, xBinaryTransferRequired, xNotHumanReadable) =>
        val extensions = Map.empty[String, String] ++
        (if (xBinaryTransferRequired == "TRUE")
           Map("X-BINARY-TRANSFER-REQUIRED" -> "TRUE")
         else Map()) ++
        (if (xNotHumanReadable == "TRUE")
           Map("X-NOT-HUMAN-READABLE" -> "TRUE")
         else Map())

        Option(LdapSyntax(LDAPOID(oid), Option(description), extensions))
      case _ => None
    }
}

case class LdapSyntax(
    oid: LDAPOID,
    description: Option[String] = None,
    extensions: Map[String, String] = Map.empty
) extends LdapSyntaxResource {
  override def toString() = {
    s"""
(
${oid} 
${description.fold("")(a => s"DESC ${a}")} 
${extensions.map(t => s"${t._1} '${t._2}'").mkString(" ")}
)"""
  }.replaceAll("[\n ]+", " ")
}

object MatchingRule extends LdapRegex {
  override val regex =
    s"\\A\\s*\\(\\s*${numericOID}\\s*(?:NAME${qDescriptions})?(?:DESC${qDString})?(OBSOLETE\\s*)?SYNTAX\\s*${numericOID}\\s*\\)\\s*\\z".r
  def apply(str: String): Option[MatchingRule] =
    str match {
      case regex(oid, names, description, isObsolete, syntax) =>
        Option(
          MatchingRule(
            oid = LDAPOID(oid),
            names = names.split(" ").toList,
            description = Option(description),
            syntax = Option(syntax).map(LDAPOID(_)),
            isObsolete = Option(isObsolete).fold(false)(_ => true)
          )
        )
      case _ => None
    }
}

case class MatchingRule(
    oid: LDAPOID,
    names: List[String],
    description: Option[String] = None,
    syntax: Option[LDAPOID],
    extensions: Map[String, String] = Map.empty,
    isObsolete: Boolean = false
) extends LdapSyntaxResource {
  override def toString() = {
    s"""
(
${oid} 
NAME ( ${names.mkString(" ")} ) 
${description.fold("")(a => s"DESC ${a}")} 
${if (isObsolete) "OBSOLETE" else ""} 
${syntax.fold("")(a => s"SYNTAX ${a.toString}")}
${extensions.map(t => s"${t._1} '${t._2}'").mkString(" ")}
)"""
  }.replaceAll("[\n ]+", " ")
}

object MatchingRuleUse extends LdapRegex {
  override val regex =
    s"\\A\\s*\\(\\s*${numericOID}\\s*(?:NAME${qDescriptions})?(?:DESCk${qDString})?(OBSOLETE\\s*)?APPLIES\\s*${OIDs}\\s*\\)\\s*\\z".r
  def apply(str: String): Option[MatchingRuleUse] =
    str match {
      case regex(oid,
                 names,
                 description,
                 isObsolete,
                 applies,
                 discardMeImStupidAndRepeatedFromApplies) =>
        Option(
          MatchingRuleUse(
            oid = LDAPOID(oid),
            names = names.split(" ").toList,
            description = Option(description),
            applies = applies.split(" $").toList.map(LDAPOID(_)),
            isObsolete = Option(isObsolete).fold(false)(_ => true)
          )
        )
      case _ => None
    }
}

case class MatchingRuleUse(
    oid: LDAPOID,
    names: List[String],
    description: Option[String] = None,
    applies: List[LDAPOID],
    extensions: Map[String, String] = Map.empty,
    isObsolete: Boolean = false
) extends LdapSyntaxResource {
  override def toString() = {
    s"""
(
${oid} 
NAME ( ${names.mkString(" ")} ) 
${description.fold("")(a => s"DESC ${a}")} 
${if (isObsolete) "OBSOLETE" else ""} 
${if (applies.isEmpty) "" else s"APPLIES ( ${applies.mkString(" $ ")} )"}
${extensions.map(t => s"${t._1} '${t._2}'").mkString(" ")}
)"""
  }.replaceAll("[\n ]+", " ")
}

import AttributeTypeUsage._

object AttributeType extends LdapRegex {
  override val regex =
    s"\\A\\s*\\(\\s*${numericOID}\\s*(?:NAME${qDescriptions})?(?:DESC${qDString})?(OBSOLETE\\s*)?(?:SUP${wOID})?(?:EQUALITY${wOID})?(?:ORDERING${wOID})?(?:SUBSTR${wOID})?(?:SYNTAX\\s*${nOIDLen}\\s*)?(SINGLE-VALUE\\s*)?(COLLECTIVE\\s*)?(NO-USER-MODIFICATION\\s*)?(?:USAGE\\s*${attributeUsage})?\\s*\\)\\s*\\z".r
  def apply(str: String): Option[AttributeType] =
    //regex.findAllMatchIn(str).toList.size
    str match {
      case regex(
          oid,
          names,
          description,
          isObsolete,
          supertype,
          equality,
          ordering,
          substringMatching,
          syntax,
          syntaxLength,
          isSingleValue,
          isCollective,
          isNotUserModifiable,
          usage
          ) =>
        Option(
          AttributeType(
            oid = LDAPOID(oid),
            names = names.split(" ").toList,
            description = Option(description),
            syntax = Option(syntax).map(LDAPOID(_)),
            syntaxLength = Option(syntaxLength).map(_.toInt),
            usage = Option(usage).map(AttributeTypeUsage.withName(_)),
            isSingleValue = Option(isSingleValue).fold(false)(_ => true),
            isCollective = Option(isCollective).fold(false)(_ => true),
            isUserModifiable = Option(isNotUserModifiable).fold(true)(_ => false), //Note it's backward,
            supertype = Option(supertype),
            substringMatching = Option(substringMatching),
            ordering = Option(ordering),
            equality = Option(equality),
            isObsolete = Option(isObsolete).fold(false)(_ => true)
          )
        )
      case _ => None
    }
}

case class AttributeType(
    oid: LDAPOID,
    names: List[String],
    description: Option[String] = None,
    syntax: Option[LDAPOID] = None,
    syntaxLength: Option[Int] = None,
    usage: Option[AttributeTypeUsage] = None,
    isSingleValue: Boolean = false,
    isCollective: Boolean = true,
    isUserModifiable: Boolean = true,
    supertype: Option[String] = None,
    substringMatching: Option[String] = None,
    ordering: Option[String] = None,
    equality: Option[String] = None,
    extensions: Map[String, String] = Map.empty,
    isObsolete: Boolean = false
) extends LdapSyntaxResource {
  override def toString() = {
    s"""
( 
${oid} 
NAME ( ${names.mkString(" ")} ) 
${description.fold("")(a => s"DESC ${a}")} 
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
${extensions.map(t => s"${t._1} '${t._2}'").mkString(" ")}
)"""
  }.replaceAll("[\n ]+", " ")
}

object ObjectClassType extends Enumeration {
  type ObjectClassType = Value
  val ABSTRACT, STRUCTURAL, AUXILIARY = Value
}

import ObjectClassType._

object ObjectClass extends LdapRegex {
  override val regex =
    s"\\A\\s*\\(\\s*${numericOID}\\s*(?:NAME${qDescriptions})?(?:DESC${qDString})?(OBSOLETE\\s*)?(?:SUP${OIDs})?(?:(ABSTRACT|STRUCTURAL|AUXILIARY)\\s*)?(?:MUST${OIDs})?(?:MAY${OIDs})?\\s*\\)\\s*\\z".r
  def apply(str: String): Option[ObjectClass] =
    str match {
      case regex(oid,
                 names,
                 description,
                 isObsolete,
                 superclasses,
                 ignore1,
                 objectClassType,
                 mandatory,
                 ignore2,
                 optional,
                 ignore3) =>
        Option(
          ObjectClass(
            oid = LDAPOID(oid),
            names = names.split(" ").toList,
            description = Option(description),
            objectClassType = Option(objectClassType).map(ObjectClassType.withName(_)),
            superclasses =
              if (superclasses != null) superclasses.split(" $ ").toList
              else List.empty,
            mandatory =
              if (mandatory != null) mandatory.split(" $ ").toList
              else List.empty,
            optional =
              if (optional != null) optional.split(" $ ").toList
              else List.empty,
            isObsolete = Option(isObsolete).fold(false)(_ => true)
          )
        )
      case _ => None
    }
}

case class ObjectClass(
    oid: LDAPOID,
    names: List[String],
    description: Option[String] = None,
    objectClassType: Option[ObjectClassType] = None,
    superclasses: List[String] = List.empty,
    mandatory: List[String] = List.empty,
    optional: List[String] = List.empty,
    extensions: Map[String, String] = Map.empty,
    isObsolete: Boolean = false
) extends LdapSyntaxResource {
  override def toString() =
    s"""
(
${oid} 
NAME ( ${names.mkString(" ")} )
${description.fold("")(a => s"DESC ${a}")}
${if (isObsolete) "OBSOLETE" else ""}
${if (superclasses.isEmpty) "" else s"SUP ( ${superclasses.mkString(" $ ")} )"}
${objectClassType.fold("")(a => s"${a}")}
${if (optional.isEmpty) "" else s"MAY ( ${optional.mkString(" $ ")} )"}
${if (mandatory.isEmpty) "" else s"MUST ( ${mandatory.mkString(" $ ")} )"}
${extensions.map(t => s"${t._1} '${t._2}'").mkString(" ")}
)
""".replaceAll("[\n ]+", " ")
}

case object SchemaNode extends ServerStructuralNode {
  override val id                    = "1cd6fba5-f4bf-40ad-8b54-c25e88c69e3e"
  override val dn                    = "cn=Subschema"
  override val structuralObjectClass = "subentry"
  override val subschemaSubentry     = "cn=Subschema"
  override val objectClass =
    List("top", "subentry", "subschema", "extensibleObject")
  override val userAttributes = Map(
    "objectClass"     -> objectClass,
    "cn"              -> List("Subschema"),
    "description"     -> List("example"),
    "ldapSyntaxes"    -> ldapSyntaxes.map(_.toString).toList,
    "matchingRules"   -> matchingRules.map(_.toString).toList,
    "matchingRuleUse" -> matchingRuleUse.map(_.toString).toList,
    "attributeTypes"  -> attributeTypes.map(_.toString).toList,
    "objectClasses"   -> objectClasses.map(_.toString).toList
  )
  def ldapSyntaxes: Seq[LdapSyntax] =
    plugins.flatMap(_.ldapSyntaxes)
  def matchingRules: Seq[MatchingRule] =
    plugins.flatMap(_.matchingRules)
  def matchingRuleUse: Seq[MatchingRuleUse] =
    plugins.flatMap(_.matchingRuleUses)
  def attributeTypes: Seq[AttributeType] =
    plugins.flatMap(_.attributeTypes)
  def objectClasses: Seq[ObjectClass] =
    plugins.flatMap(_.objectClasses)
}

object BaseSchemaPlugin extends Plugin {
  val schemas = List(
    "base.schema",
    "fusionDirectory.schema",
    "globe_internet.schema",
    "gonicus.schema",
    "gosa.schema",
    "openldap.schema",
    "RFC1274.schema",
    "RFC2079.schema",
    "RFC2247.schema",
    "RFC2256.schema",
    "RFC2307.schema",
    "RFC2377.schema",
    "RFC2587.schema",
    "RFC2589.schema",
    "RFC2798.schema",
    "RFC3045.schema",
    "RFC3296.schema",
    "RFC3672.schema",
    "RFC4512.schema",
    "RFC4519.schema",
    "RFC4530.schema",
    "samba.schema",
    "sunldap.schema"
  )

  private def read = {
    val all =
      schemas.map(schema => {
        println(schema)
        readSchemaFile(File.resource(s"schemas/${schema}"))
      })
    all.foldLeft(
      (Seq.empty[LdapSyntax],
       Seq.empty[AttributeType],
       Seq.empty[MatchingRule],
       Seq.empty[MatchingRuleUse],
       Seq.empty[ObjectClass])
    ) { (previous, tuple) =>
      (previous._1 ++ tuple._1,
       previous._2 ++ tuple._2,
       previous._3 ++ tuple._3,
       previous._4 ++ tuple._4,
       previous._5 ++ tuple._5)
    }
  }

  override val (ldapSyntaxes: Seq[LdapSyntax],
                attributeTypes: Seq[AttributeType],
                matchingRules: Seq[MatchingRule],
                matchingRuleUses: Seq[MatchingRuleUse],
                objectClasses: Seq[ObjectClass]) = read
}
