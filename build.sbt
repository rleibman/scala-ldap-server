/*
 *   Copyright (C) 2016  Roberto Leibman
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

name := "scala-ldap-server"

organization := "com.dienique"

version := "0.0.4"

scalaVersion := "2.12.2"

lazy val akkaVersion = "2.5.1"

///////////////////////////////////////////////////////////////////////////
// Packaging Stuff
enablePlugins(LinuxPlugin)
enablePlugins(JDebPackaging)
enablePlugins(RpmPlugin, RpmDeployPlugin)
enablePlugins(DebianPlugin, DebianDeployPlugin)
enablePlugins(JavaServerAppPackaging)

import com.typesafe.sbt.packager.archetypes.ServerLoader

serverLoading in Debian := ServerLoader.Upstart

com.typesafe.sbt.packager.SettingsHelper.makeDeploymentSettings(Debian, packageBin in Debian, "deb")

//debianChangelog in Debian := Some(file("src/debian/changelog"))

packageDescription in Debian := "An LDAP Server in Scala"
packageSummary in Debian := "An LDAP Server in Scala"
maintainer in Linux := "Roberto Leibman <roberto@leibman.net>"
packageSummary in Linux := "An LDAP Server in Scala"
packageDescription := "An LDAP Server in Scala"
daemonUser in Linux := normalizedName.value
daemonGroup in Linux := normalizedName.value

rpmVendor  := "Roberto leibman"
rpmLicense := Some("GNU GENERAL PUBLIC LICENSE")

mappings in Universal += {
	val src = sourceDirectory.value
    val conf = src / "templates" / "application.conf"
    conf -> "conf/application.conf"
}
///////////////////////////////////////////////////////////////////////////

libraryDependencies += "com.typesafe.akka"    %% "akka-slf4j"       % akkaVersion withSources()
libraryDependencies += "com.github.pathikrit" %% "better-files" % "3.0.0" withSources()
libraryDependencies += "com.typesafe.akka" %% "akka-actor" % akkaVersion  withSources()
libraryDependencies += "com.typesafe.akka" %% "akka-testkit" % akkaVersion withSources()
libraryDependencies += "com.typesafe.akka"  %% "akka-stream" % akkaVersion withSources()
libraryDependencies += "org.reactivemongo" %% "reactivemongo" % "0.12.3" withSources()
libraryDependencies += "ch.qos.logback"        % "logback-classic"  % "1.2.3"
libraryDependencies += "ch.qos.logback"        % "logback-core"  % "1.2.3"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.0.3" % "test" withSources()
libraryDependencies += "com.typesafe.akka"  %% "akka-testkit" % akkaVersion % "compile,  test" withSources()

scalacOptions ++= Seq(
  "-unchecked",                        // Enable additional warnings where generated code depends on assumptions.
  "-deprecation",                      // Emit warning and location for usages of deprecated APIs.
  "-encoding", "utf-8",                // Specify character encoding used by source files.
  "-feature",                          // Emit warning and location for usages of features that should be imported explicitly.
  "-Ywarn-dead-code",                  // Warn when dead code is identified.
//  "-Yno-adapted-args",                 // Do not adapt an argument list (either by inserting () or creating a tuple) to match the receiver.
  "-Ywarn-numeric-widen",              // Warn when numerics are widened.
  "-Ywarn-value-discard",              // Warn when non-Unit expression results are unused.
  "-Xfuture",                          // Turn on future language features.
  "-Ywarn-unused:imports",             // Warn if an import selector is not referenced.
  "-language:existentials",            // Existential types (besides wildcard types) can be written and inferred
  "-language:experimental.macros",     // Allow macro definition (besides implementation and application)
  "-language:higherKinds",             // Allow higher-kinded types
  "-language:implicitConversions",      // Allow definition of implicit functions called views
  "-language:postfixOps",
  "-explaintypes",                     // Explain type errors in more detail.
  "-Xcheckinit",                       // Wrap field accessors to throw an exception on uninitialized access.
//  "-Xfatal-warnings",                  // Fail the compilation if there are any warnings.
//  "-Xlint:adapted-args",               // Warn if an argument list is modified to match the receiver.
  "-Xlint:by-name-right-associative",  // By-name parameter of right associative operator.
  "-Xlint:constant",                   // Evaluation of a constant arithmetic expression results in an error.
  "-Xlint:delayedinit-select",         // Selecting member of DelayedInit.
  "-Xlint:doc-detached",               // A Scaladoc comment appears to be detached from its element.
  "-Xlint:inaccessible",              // Warn about inaccessible types in method signatures.
  "-Xlint:infer-any",                  // Warn when a type argument is inferred to be `Any`.
  "-Xlint:missing-interpolator",       // A string literal appears to be missing an interpolator id.
  "-Xlint:nullary-override",           // Warn when non-nullary `def f()' overrides nullary `def f'.
  "-Xlint:nullary-unit",               // Warn when nullary methods return Unit.
  "-Xlint:option-implicit",            // Option.apply used implicit view.
  "-Xlint:package-object-classes",     // Class or object defined in package object.
  "-Xlint:poly-implicit-overload",     // Parameterized overloaded implicit methods are not visible as view bounds.
  "-Xlint:private-shadow",             // A private field (or class parameter) shadows a superclass field.
  "-Xlint:stars-align",                // Pattern sequence wildcard must align with sequence component.
  "-Xlint:type-parameter-shadow",      // A local type parameter shadows a type already in scope.
  "-Xlint:unsound-match",              // Pattern match may not be typesafe.
  "-Ypartial-unification",             // Enable partial unification in type constructor inference
  "-Ywarn-extra-implicit",             // Warn when more than one implicit parameter section is defined.
  "-Ywarn-inaccessible",               // Warn about inaccessible types in method signatures.
  "-Ywarn-infer-any",                  // Warn when a type argument is inferred to be `Any`.
  "-Ywarn-nullary-override",           // Warn when non-nullary `def f()' overrides nullary `def f'.
  "-Ywarn-nullary-unit",               // Warn when nullary methods return Unit.
  "-Ywarn-unused:implicits",           // Warn if an implicit parameter is unused.
  "-Ywarn-unused:locals",              // Warn if a local definition is unused.
  "-Ywarn-unused:params",              // Warn if a value parameter is unused.
  "-Ywarn-unused:patvars",             // Warn if a variable bound in a pattern is unused.
  "-Ywarn-unused:privates"            // Warn if a private member is unused.
)

Revolver.settings
// Revolver.enableDebugging(port = 9999, suspend = true)

fork in run := true

enablePlugins(BuildInfoPlugin)

buildInfoOptions += BuildInfoOption.ToJson
buildInfoOptions += BuildInfoOption.BuildTime
buildInfoKeys := Seq[BuildInfoKey](name, version, scalaVersion, sbtVersion)
buildInfoPackage := "buildinfo"

// EclipseKeys.createSrc := EclipseCreateSrc.Default + EclipseCreateSrc.ManagedSrc 
// EclipseKeys.configurations := Set(Configurations.Compile, Configurations.Test, Configurations.IntegrationTest)
