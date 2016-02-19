resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots"

addSbtPlugin("com.typesafe.sbt" % "sbt-native-packager" % "0.8.0")
addSbtPlugin("io.spray" % "sbt-revolver" % "0.7.2")
addSbtPlugin("net.virtual-void" % "sbt-dependency-graph" % "0.7.5")
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "0.13.0")
addSbtPlugin("org.scoverage" % "sbt-scoverage" % "1.3.3")
addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.1.9")
addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.5.0")