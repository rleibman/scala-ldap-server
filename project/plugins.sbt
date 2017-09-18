resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots"
resolvers += "Bintray" at "https://dl.bintray.com/sbt/sbt-plugin-releases"

libraryDependencies += "org.vafer" % "jdeb" % "1.5" artifacts (Artifact("jdeb",
                                                                        "jar",
                                                                        "jar"))
addSbtPlugin("com.dwijnand"      % "sbt-travisci"    % "1.1.1")
addSbtPlugin("com.typesafe.sbt"  % "sbt-git"         % "0.9.3")
addSbtPlugin("com.lucidchart"    % "sbt-scalafmt"    % "1.10")
addSbtPlugin("de.heikoseeberger" % "sbt-header"      % "3.0.1")

libraryDependencies += "org.slf4j" % "slf4j-nop" % "1.7.25" // Needed by sbt-git


//addSbtPlugin("com.typesafe.sbt" % "sbt-native-packager" % "1.2.0")
addSbtPlugin("io.spray" % "sbt-revolver" % "0.9.0")
//addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "0.14.5")
addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.7.0")
