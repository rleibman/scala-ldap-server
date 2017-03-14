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
package asn1

sealed abstract class Asn1Object {
}

case class Asn1Sequence(value: Asn1Object*) extends Asn1Object {
}

case class Asn1Set(val value: Set[Asn1Object]) extends Asn1Object {
}

object Asn1Set {
  val empty = Asn1Set()
  def apply(value: Asn1Object*): Asn1Set = Asn1Set(value.toSet)
}

sealed abstract class Asn1Boolean extends Asn1Object {
  def value: Boolean
}
case object Asn1True extends Asn1Boolean {
  override def value = true
}
case object Asn1False extends Asn1Boolean {
  override def value = false
}
object Asn1Boolean {
  def apply(x: Boolean): Asn1Boolean = if (x) Asn1True else Asn1False
  def unapply(x: Asn1Boolean): Option[Boolean] = Some(x.value)
}

object Asn1Number {
  def apply() = Asn1Zero()
  def apply(value: Byte) = Asn1Byte(value)
  def apply(value: Short) = Asn1Short(value)
  def apply(value: Int) = Asn1Int(value)
  def apply(value: Long) = Asn1Long(value)
  def apply(value: Double) = Asn1Double(value)
}
case class Asn1Zero() extends Asn1Object
case class Asn1Byte(value: Byte) extends Asn1Object
case class Asn1Int(value: Int) extends Asn1Object
case class Asn1Short(value: Short) extends Asn1Object
case class Asn1Long(value: Long) extends Asn1Object
case class Asn1Double(value: Double) extends Asn1Object

case class Asn1ContextSpecific(tag: Byte, value: Array[Byte]) extends Asn1Object {
  override def toString = s"Asn1ContextSpecific(${value.map(_.toHexString).mkString(", 0x")})"
  override def equals(obj: Any) = {
    if (!obj.isInstanceOf[Asn1ContextSpecific]) {
      false
    } else {
      value.toList == obj.asInstanceOf[Asn1ContextSpecific].value.toList
    }
  }
}

case class Asn1Null() extends Asn1Object

case class Asn1String(value: String) extends Asn1Object

case class Asn1Enumerated(value: Short) extends Asn1Object

object Asn1Enumerated {
  def apply[T <: Enumeration#Value](value: T): Asn1Enumerated = Asn1Enumerated(value.id.toByte)
}

case class Asn1ObjectIdentifier(value: Array[Byte]) extends Asn1Object {
  override def toString = s"Asn1ContextSpecific(${value.map(_.toHexString).mkString(", 0x")})"
}

case class Asn1Application(tag: Int, value: Asn1Object*) extends Asn1Object
