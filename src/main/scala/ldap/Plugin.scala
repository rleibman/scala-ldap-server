package ldap

import asn1.Asn1Object
import asn1.Asn1Application
import scala.concurrent.Future
import better.files.File
import dao.DAO

trait Plugin {
  def initialize(config: com.typesafe.config.Config): Future[Unit] = Future.successful {}
  def terminate(): Future[Unit] = Future.successful {}
  def resultTypes(): Seq[LDAPResultType] = Seq.empty
  def supportedControls: Seq[ldap.SupportedControl] = Seq.empty
  def supportedExtensions: Seq[ldap.SupportedExtension] = Seq.empty
  def supportedFeatures: Seq[ldap.SupportedFeature] = Seq.empty
  def encodeControl(control: Control): Option[Asn1Object] = None
  def encode(msg: LdapMessage): Option[Asn1Object] = None
  def decodeApplication(applicationAsn1: Asn1Application): Option[MessageProtocolOp] = None
  def decodeControl(controlAsn1: Asn1Object): Option[Control] = None
  def operate(msg: LdapMessage, preResults: Seq[LdapMessage], dao: DAO): Future[Seq[LdapMessage]] = Future.successful(preResults)
  def ldapSyntaxes: Seq[LdapSyntax] = Seq.empty
  def matchingRules: Seq[MatchingRule] = Seq.empty
  def matchingRuleUses: Seq[MatchingRuleUse] = Seq.empty
  def attributeTypes: Seq[AttributeType] = Seq.empty
  def objectClasses: Seq[ObjectClass] = Seq.empty

  def readSchemaFile(file: File) = {
    val lineRegex = "(attributeTypes:|objectClasses:|ldapSyntaxes:|matchingRules:|matchingRuleUse:)(.*)".r
    val resources = file.lineIterator.map { line =>
      (line match {
        case lineRegex(lineType, src) =>
          lineType match {
            case "attributeTypes:" => AttributeType(src)
            case "objectClasses:" => ObjectClass(src)
            case "ldapSyntaxes:" => LdapSyntax(src)
            case "matchingRules:" => MatchingRule(src)
            case "matchingRuleUse:" => MatchingRuleUse(src)
          }
      }).toSeq
    }
    resources.flatten.foldLeft((Seq.empty[LdapSyntax], Seq.empty[AttributeType], Seq.empty[MatchingRule], Seq.empty[MatchingRuleUse], Seq.empty[ObjectClass])) {
      (previous, resource) =>
        resource match {
          case resource: LdapSyntax => (previous._1 :+ resource, previous._2, previous._3, previous._4, previous._5)
          case resource: AttributeType => (previous._1, previous._2 :+ resource, previous._3, previous._4, previous._5)
          case resource: MatchingRule => (previous._1, previous._2, previous._3 :+ resource, previous._4, previous._5)
          case resource: MatchingRuleUse => (previous._1, previous._2, previous._3, previous._4 :+ resource, previous._5)
          case resource: ObjectClass => (previous._1, previous._2, previous._3, previous._4, previous._5 :+ resource)
        }
    }
  }

}