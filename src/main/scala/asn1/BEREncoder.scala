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

import java.nio.ByteOrder

import scala.annotation.tailrec

import akka.util.ByteIterator

import akka.util.ByteString
import akka.util.ByteStringBuilder

object BEREncoder extends Asn1Encoder {
  object PrimitiveOrConstructed extends Enumeration {
    type PrimitiveOrConstructed = Value
    val primitive, constructed = Value
    def apply(byte: Byte): PrimitiveOrConstructed = (byte & 0x20) >> 5 match {
      case 0 ⇒ primitive
      case 1 ⇒ constructed
    }
  }

  object Asn1IdentifierType extends Enumeration {
    type Asn1IdentifierType = Value
    val universal, application, contextSpecific, privateType = Value
    def apply(byte: Byte): Asn1IdentifierType = (byte & 0xC0) >> 6 match {
      case 0 ⇒ universal
      case 1 ⇒ application
      case 2 ⇒ contextSpecific
      case 3 ⇒ privateType
    }
  }

  import PrimitiveOrConstructed._
  import Asn1IdentifierType._
  def encode(obj: Asn1Object): ByteString = {
    val bb = new ByteStringBuilder

    def loop(obj: Asn1Object, bb: ByteStringBuilder): ByteStringBuilder = {
      obj match {
        case Asn1Null() ⇒
          bb
        //Do nothing

        case Asn1ContextSpecific(value) ⇒
          bb.putByte((0x80 //Class (context Specific)
            | 0x00 //Primitive or constructed (primitive)
            | 0x00 //Tag (x)
            ).toByte)
          bb.putByte((0x00 //short form
            | value.length //length
            ).toByte)
          bb.putBytes(value)
        case Asn1Application(tag, value @ _*) ⇒
          val newBB = new ByteStringBuilder
          value.foreach(loop(_, newBB))
          val bytes = newBB.result()
          bb.putByte((0x40 //Class (application)
            | 0x20 //Primitive or constructed (constructed)
            | tag //Tag (applicationTag)
            ).toByte)
          bb.putByte((0x00 //short form
            | bytes.size //length
            ).toByte)
          bb.putBytes(bytes.toArray)
        case Asn1Int(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
            ).toByte)
          bb.putByte(0x00 //short form
            | 0x04 //length
            )
          bb.putInt(value)(ByteOrder.BIG_ENDIAN)
        case Asn1Boolean(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x01 //Tag (int)
            ).toByte)
          bb.putByte(if (value) 1 else 0)
        case Asn1Long(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
            ).toByte)
          bb.putByte(0x00 //short form
            | 0x08 //length
            )
          bb.putLong(value)(ByteOrder.BIG_ENDIAN)
        case Asn1Short(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
            ).toByte)
          bb.putByte(0x00 //short form
            | 0x02 //length
            )
          bb.putShort(value)(ByteOrder.BIG_ENDIAN)
        case Asn1Byte(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
            ).toByte)
          bb.putByte(0x00 //short form
            | 0x01 //length
            )
          bb.putByte(value)
        case Asn1Enumerated(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x0a //Tag (enumerated)
            ).toByte)
          bb.putByte(0x00 //short form
            | 0x01 //length
            )
          bb.putByte(value)
        case Asn1String(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x04 //Tag (String)
            ).toByte)
          bb.putByte((0x00 //short form
            | value.size //length
            ).toByte)
          bb.putBytes(value.toCharArray().map(_.toByte))
        case Asn1Sequence(value @ _*) ⇒
          val newBB = new ByteStringBuilder
          value.foreach(a ⇒ loop(a, newBB))
          val bytes = newBB.result()

          bb.putByte((0x00 //Class (universal)
            | 0x20 //Primitive or constructed (constructed)
            | 0x10 //Tag (x)
            ).toByte)
          bb.putByte((0x00 //short form
            | bytes.size //length
            ).toByte)
          bb.putBytes(bytes.toArray)
        case a ⇒ throw new Error(s"Unknown type of Asn1Object ${obj}")
      }
    }
    loop(obj, bb)

    bb.result
  }
  def decode(str: ByteString): Asn1Object = {
    @tailrec def loop(iter: ByteIterator, acc: List[Asn1Object]): List[Asn1Object] = {
      if (!iter.hasNext) {
        acc
      } else {
        val obj = once(iter)
        loop(iter, acc :+ obj)
      }
    }
    def once(iter: ByteIterator): Asn1Object = {
      if (!iter.hasNext) {
        Asn1Null()
      } else {

        val identifierOctet = iter.getByte
        val identifierType = Asn1IdentifierType(identifierOctet)
        val pORc = PrimitiveOrConstructed(identifierOctet)
        val classTag = identifierOctet & 0x1F
        val lengthOctet = iter.getByte
        val length = if ((lengthOctet & 0x80) > 0) {
          val lengthlength = lengthOctet & 0x7F
          if (lengthlength == 0) {
            //Constructed
            0
          } else {
            val lengthBytes = iter.getBytes(lengthlength)
            BigInt(1, lengthBytes).toInt
          }

        } else {
          lengthOctet & 0x7F
        }

        //        println(s"(identifierType, pORc, classTag, lengthOctet, length) = ${(identifierType, pORc, classTag.toHexString, lengthOctet.toHexString, length)}")
        //      println(s"iter.clone().size=${iter.clone().size}")

        val res = identifierType match {
          case Asn1IdentifierType.application ⇒
            Asn1Application(classTag, loop(iter.take(length), List()): _*)
          case Asn1IdentifierType.contextSpecific ⇒
            Asn1ContextSpecific(iter.take(length).toArray)
          case Asn1IdentifierType.universal ⇒
            classTag match {
              case 0x00 ⇒ null //END OF CONTENT
              case 0x01 ⇒
                val value = iter.getByte
                Asn1Boolean(value != 0)
              case 0x02 ⇒
                length match {
                  case 1 ⇒ Asn1Byte(iter.getByte)
                  case 2 ⇒ Asn1Short(iter.getShort(ByteOrder.BIG_ENDIAN))
                  case 3 ⇒ Asn1Int(BigInt(iter.getBytes(length)).toInt)
                  case 4 ⇒ Asn1Int(iter.getInt(ByteOrder.BIG_ENDIAN))
                  case _ ⇒
                    val value = BigInt(iter.getBytes(length)).toLong
                    Asn1Long(value)
                }
              case 0x03 ⇒ //Bit String
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x04 ⇒ //OCTET STRING
                val value = iter.getBytes(length).map(_.toChar).mkString
                Asn1String(value)
              case 0x05 ⇒ Asn1Null()
              case 0x06 ⇒ Asn1ObjectIdentifier(iter.take(length).toArray)
              case 0x07 ⇒ //Object Descriptor
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x08 ⇒ //External
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x09 ⇒ //Real
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x0A ⇒
                Asn1Enumerated(iter.getByte)
              case 0x0B ⇒ //Embedded PDV
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x0C ⇒ //UTF-8 String
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x0D ⇒ //Relative OID
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x10 ⇒
                Asn1Sequence(loop(iter.take(length), List()): _*)
              case 0x11 ⇒
                Asn1Set(loop(iter.take(length), List()): _*)
              case 0x12 ⇒ //NumericString
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x13 ⇒ //PrintableString
                val value = iter.getBytes(length).map(_.toChar).mkString
                Asn1String(value)
              case 0x14 ⇒ //T61String
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x15 ⇒ //VideotexString
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x16 ⇒ //IA5String
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x17 ⇒ //UTCTime
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x18 ⇒ //GeneralizedTime
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x19 ⇒ //GraphicString
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1A ⇒ //VisibleString
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1B ⇒ //GeneralString
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1C ⇒ //UniversalString
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1D ⇒ //CHARACTER STRING
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1E ⇒ //BMPString
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1F ⇒ //Use long form
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")

              case _ ⇒ throw new Error(s"Unkown classTag 0x${classTag.toHexString}")
            }
        }
        return res
      }
    }

    val iter = str.iterator
    val result = once(iter)
    result
  }
}
