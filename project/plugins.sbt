resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots"

addSbtPlugin("com.typesafe.sbt" % "sbt-native-packager" % "0.8.0")
addSbtPlugin("io.spray" % "sbt-revolver" % "0.7.2")
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "0.13.0")
addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.5.0")