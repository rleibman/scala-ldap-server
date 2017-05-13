package ldap

import better.files.File
import com.typesafe.config.ConfigFactory
import ldap.rfc4533.RFC4533Plugin
import java.time.format.DateTimeFormatter

trait Config {
  val config: com.typesafe.config.Config = {
    val confFileName = System.getProperty("application.conf", "./src/templates/application.conf")
    val confFile = File(confFileName)
    val config = ConfigFactory
      .parseFile(confFile.toJava)
      .withFallback(ConfigFactory.load())
    config
  }
  val baseDN = config.getString("scala-ldap-server.base")
  val plugins: Seq[Plugin] = Seq(BaseSchemaPlugin, RFC4533Plugin)
  def defaultOperationalAttributes(structuralObjectClass: String) = {
    val date = java.time.ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssZ"))
    Map(
      "creatorsName" -> List(s"cn=Manager,${baseDN}"),
      "createTimestamp" -> List(date),
      "modifiersName" -> List(s"cn=Manager,${baseDN}"),
      "modifyTimestamp" -> List(date),
      "structuralObjectClass" -> List(structuralObjectClass),
      "subschemaSubentry" -> List("cn=Subschema")
    )
  }
}
