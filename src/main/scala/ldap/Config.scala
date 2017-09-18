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

import better.files.File
import com.typesafe.config.ConfigFactory
import ldap.rfc4533.RFC4533Plugin
import java.time.format.DateTimeFormatter
import ldap.rfc3062.RFC3062Plugin
import ldap.rfc2830.RFC2830Plugin

trait Config {
  val config: com.typesafe.config.Config = {
    val confFileName =
      System.getProperty("application.conf", "./src/templates/application.conf")
    val confFile = File(confFileName)
    val config = ConfigFactory
      .parseFile(confFile.toJava)
      .withFallback(ConfigFactory.load())
    config
  }
  val baseDN               = config.getString("scala-ldap-server.base")
  def plugins: Seq[Plugin] = Seq(BaseSchemaPlugin, RFC4533Plugin, RFC3062Plugin, RFC2830Plugin)
  def defaultOperationalAttributes(structuralObjectClass: String) = {
    val date = java.time.ZonedDateTime
      .now()
      .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssZ"))
    Map(
      "creatorsName"          -> List(s"cn=Manager,${baseDN}"),
      "createTimestamp"       -> List(date),
      "modifiersName"         -> List(s"cn=Manager,${baseDN}"),
      "modifyTimestamp"       -> List(date),
      "structuralObjectClass" -> List(structuralObjectClass),
      "subschemaSubentry"     -> List("cn=Subschema")
    )
  }
}
