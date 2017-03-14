package ldap

import better.files.File
import com.typesafe.config.ConfigFactory
import ldap.rfc4533.RFC4533Plugin

trait Config {
  val config: com.typesafe.config.Config = {
    val confFileName = System.getProperty("application.conf", "./src/templates/application.conf")
    val confFile = File(confFileName)
    val config = ConfigFactory
      .parseFile(confFile.toJava)
      .withFallback(ConfigFactory.load())
    config
  }
  val plugins: Seq[Plugin] = Seq(RFC4533Plugin)
}
