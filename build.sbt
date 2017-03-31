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

scalaVersion := "2.12.1"

lazy val akkaVersion = "2.4.17"

libraryDependencies += "com.github.pathikrit" %% "better-files" % "3.0.0" withSources()
libraryDependencies += "com.typesafe.akka" %% "akka-actor" % akkaVersion  withSources()
libraryDependencies += "com.typesafe.akka" %% "akka-testkit" % akkaVersion withSources()
libraryDependencies += "com.typesafe.akka"  %% "akka-stream" % akkaVersion withSources()
libraryDependencies += "org.reactivemongo" %% "reactivemongo" % "0.12.1" withSources()
libraryDependencies += "ch.qos.logback"      % "logback-classic"  % "1.2.2"
libraryDependencies += "ch.qos.logback"      % "logback-core"  % "1.2.2"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.0.1" % "test" withSources()
libraryDependencies += "com.typesafe.akka"  %% "akka-testkit" % akkaVersion % "compile,  test" withSources()

scalacOptions ++= Seq(
  "-unchecked",
  "-deprecation",
  "-encoding", "UTF-8",
  "-feature",                
  "-Xlint",
  "-Ywarn-dead-code",
  "-Yno-adapted-args",       
  "-Ywarn-numeric-widen",   
  "-Ywarn-value-discard",
  "-Xfuture",
  "-Ywarn-unused-import",
  "-Ywarn-unused",
  "-Ywarn-dead-code",
  "-Ywarn-numeric-widen",
  //"-Xfatal-warnings",
  "-language:_",
  "-target:jvm-1.8",
  "-language:existentials",
  "-language:higherKinds",
  "-language:implicitConversions"
)

Revolver.settings
//Revolver.enableDebugging(port = 9999, suspend = true)

fork in run := true