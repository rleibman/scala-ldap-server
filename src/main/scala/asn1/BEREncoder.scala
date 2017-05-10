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

  def encode(obj: Asn1Object): ByteString = {
    val bb = new ByteStringBuilder

    def loop(obj: Asn1Object, bb: ByteStringBuilder): ByteStringBuilder = {
      def putSize(size: Long) = {
        if (size < 0x80) {
          bb.putByte((0x00 | size).toByte)
        } else if (size == 0x80) {
          throw new RuntimeException("Indefinite lengths not yet supported")
        } else if (size < 0x100) {
          bb.putByte((0x80 | 0x01).toByte)
          bb.putByte(size.toByte)
        } else if (size < 0x10000) {
          bb.putByte((0x80 | 0x02).toByte)
          bb.putShort(size.toShort)(ByteOrder.BIG_ENDIAN)
        } else if (size < 0x100000000L) {
          bb.putByte((0x80 | 0x04).toByte)
          bb.putInt(size.toInt)(ByteOrder.BIG_ENDIAN)
        } else {
          bb.putByte((0x80 | 0x08).toByte)
          bb.putLong(size)(ByteOrder.BIG_ENDIAN)
        }
      }
      obj match {
        case Asn1Null ⇒
          bb
        //Do nothing

        case Asn1ContextSpecific(tag, value) ⇒
          bb.putByte((0x80 //Class (context Specific)
            | 0x00 //Primitive or constructed (primitive)
            | tag //Tag (x)
          ).toByte)
          putSize(value.length.toLong)
          bb.putBytes(value)
        case Asn1Application(tag, value @ _*) ⇒ {
          val newBB = new ByteStringBuilder
          value.foreach(loop(_, newBB))
          val bytes = newBB.result()
          bb.putByte((0x40 //Class (application)
            | { if (bytes.size > 1) 0x20 else 0x00 } //Primitive or constructed (constructed)
            | tag //Tag (applicationTag)
          ).toByte)
          if (bytes.size > 0) {
            putSize(bytes.size.toLong)
            bb.putBytes(bytes.toArray)
          }
          bb
        }
        case Asn1Int(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
          ).toByte)
          putSize(4)
          bb.putInt(value)(ByteOrder.BIG_ENDIAN)
        case Asn1Boolean(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x01 //Tag (int)
          ).toByte)
          putSize(1)
          bb.putByte(if (value) 1 else 0)
        case Asn1Long(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
          ).toByte)
          putSize(8)
          bb.putLong(value)(ByteOrder.BIG_ENDIAN)
        case Asn1Short(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
          ).toByte)
          putSize(2)
          bb.putShort(value.toShort)(ByteOrder.BIG_ENDIAN)
        case Asn1Zero() ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
          ).toByte)
          bb
        case Asn1Byte(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x02 //Tag (int)
          ).toByte)
          putSize(1)
          bb.putByte(value)
          bb
        case Asn1Enumerated(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x0a //Tag (enumerated)
          ).toByte)
          //Yeah, we could figure out how big this needs to be, but that's extra processing, and who needs that?
          putSize(4)
          bb.putInt(value)(ByteOrder.BIG_ENDIAN)
        case Asn1String(value) ⇒
          bb.putByte((0x00 //Class (universal)
            | 0x00 //Primitive or constructed (primitive)
            | 0x04 //Tag (String)
          ).toByte)
          putSize(value.size.toLong)
          bb.putBytes(value.toCharArray().map(_.toByte))
        case Asn1Sequence(value @ _*) ⇒
          val newBB = new ByteStringBuilder
          value.foreach(a ⇒ loop(a, newBB))
          val bytes = newBB.result()

          bb.putByte((0x00 //Class (universal)
            | 0x20 //Primitive or constructed (constructed)
            | 0x10 //Tag (x)
          ).toByte)
          putSize(bytes.size.toLong)
          bb.putBytes(bytes.toArray)
        case Asn1Set(value) ⇒
          val newBB = new ByteStringBuilder
          value.foreach(a ⇒ loop(a, newBB))
          val bytes = newBB.result()

          bb.putByte((0x00 //Class (universal)
            | 0x20 //Primitive or constructed (constructed)
            | 0x11 //Tag (x)
          ).toByte)
          putSize(bytes.size.toLong)
          bb.putBytes(bytes.toArray)
        case Asn1BitString(_) =>
          //TODO handle this
          throw new Error(s"Unhandled type of Asn1Object ${obj}")
        case _ ⇒ throw new Error(s"Unknown type of Asn1Object ${obj}")
      }
    }
    loop(obj, bb)

    bb.result
  }

  def decode(str: ByteString): List[Asn1Object] = {
    @tailrec def loop(str: ByteString, acc: List[Asn1Object]): List[Asn1Object] = {
      if (str.isEmpty) {
        acc
      } else {
        val obj = once(str)
        loop(obj._2, acc :+ obj._1)
      }
    }
    def once(str: ByteString): (Asn1Object, ByteString) = {
      try {
        //        val b = iter.clone.toArray.map(_.formatted("%02X").takeRight(2)).mkString(" ")
        if (str.isEmpty) {
          return (Asn1Null, ByteString.empty) //I don't like doing this, but it really is very simple, there's nothing left in the stream, so just bail
        }
        val iter = str.iterator
        val identifierOctet = iter.getByte
        val identifierType = Asn1IdentifierType(identifierOctet)
        //        val pORc = PrimitiveOrConstructed(identifierOctet)
        val classTag = (identifierOctet & 0x1F).toInt
        //        if (!iter.hasNext) {
        //          //I don't like doing this, but it really is very simple, there's nothing left in the stream, so just bail.
        //          //In the case of LDAP, we have the following
        //          // UnbindRequest ::= [APPLICATION 2] NULL
        //          return Asn1Null
        //        }
        val length = {
          if (!iter.hasNext) {
            0
          } else {
            val lengthOctet = iter.getByte
            if ((lengthOctet & 0x80) > 0) {
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
          }
        }

        //        println(s"(identifierType, pORc, classTag, length) = ${(identifierType, pORc, classTag.toHexString, length)}")
        //      println(s"iter.clone().size=${iter.clone().size}")

        val res = identifierType match {
          case Asn1IdentifierType.application ⇒
            Asn1Application(classTag, loop(iter.getByteString(length), List()): _*)
          case Asn1IdentifierType.contextSpecific ⇒
            Asn1ContextSpecific(classTag, iter.getBytes(length))
          case Asn1IdentifierType.universal ⇒
            classTag match {
              case 0x00 ⇒ null //END OF CONTENT
              case 0x01 ⇒
                val value = iter.getByte
                Asn1Boolean(value != 0)
              case 0x02 ⇒
                length match {
                  case 0 ⇒ Asn1Zero()
                  case 1 ⇒ Asn1Byte(iter.getByte)
                  case 2 ⇒ Asn1Short(iter.getShort(ByteOrder.BIG_ENDIAN))
                  case 3 ⇒ Asn1Int(BigInt(iter.getBytes(length)).toInt)
                  case 4 ⇒ Asn1Int(iter.getInt(ByteOrder.BIG_ENDIAN))
                  case _ ⇒
                    val value = BigInt(iter.getBytes(length)).toLong
                    Asn1Long(value)
                }
              case 0x03 ⇒ //Bit String
                val value = iter.getBytes(length).map(_.toChar).mkString
                Asn1BitString(value)
              case 0x04 ⇒ //OCTET STRING
                val value = iter.getBytes(length).map(_.toChar).mkString
                Asn1String(value)
              case 0x05 ⇒ Asn1Null
              case 0x06 ⇒ Asn1ObjectIdentifier(iter.getBytes(length))
              case 0x07 ⇒ //Object Descriptor
                val value = iter.getBytes(length).map(_.toChar).mkString
                Asn1ObjectDescriptor(value)
              case 0x08 ⇒ //External
                Asn1External()
              //                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x09 ⇒ //Real
                Asn1Double(0.0) //TODO fix this
              //                val preamble = iter.getByte
              //                val result = if ((preamble & 0x40) == 1) {
              //                  Double.PositiveInfinity
              //                } else if ((preamble & 0x41) == 1) {
              //                  Double.NegativeInfinity
              //                } else {
              //                  val szOfExp = 1 + (preamble & 0x3)
              //                  val sign = preamble & 0x40
              //                  val ff = (preamble & 0x0C) >> 2
              //                  var exponent = BigInt(iter.getBytes(szOfExp)).toLong
              //                  val mantissaEncFrm = BigInt(iter.getBytes(length - szOfExp - 1)).toLong
              //                  var mantissa = mantissaEncFrm << ff
              //                  while ((mantissa & 0x000ff00000000000L) == 0x0) {
              //                    exponent = exponent - 8
              //                    mantissa = mantissa << 8
              //                  }
              //                  while ((mantissa & 0x0010000000000000L) == 0x0) {
              //                    exponent = exponent - 1
              //                    mantissa = mantissa << 1
              //                  }
              //                  mantissa &= 0x0FFFFFFFFFFFFFL
              //                  var value = ((exponent + 1023 + 52) << 52) | mantissa
              //                  if (sign == 1) {
              //                    value = value | 0x8000000000000000L
              //                  }
              //                  java.lang.Double.longBitsToDouble(value);
              //                }
              //
              //                Asn1Double(result)
              case 0x0A ⇒
                val num = length match {
                  case 1 ⇒ iter.getByte.toInt
                  case 2 ⇒ iter.getShort(ByteOrder.BIG_ENDIAN).toInt
                  case 3 ⇒ BigInt(iter.getBytes(length)).toInt
                  case 4 ⇒ iter.getInt(ByteOrder.BIG_ENDIAN).toInt
                  case _ ⇒
                    throw new Error(s"${length} length is not supported for enumerated values")
                }
                Asn1Enumerated(num)
              case 0x0B ⇒ //Embedded PDV
                Asn1EmbeddedPDV(iter.getBytes(length)) //TODO do something with the data (https://www.obj-sys.com/asn1tutorial/node125.html)
              case 0x0C ⇒ //UTF-8 String
                //TODO check this
                val value = iter.getBytes(length).map(_.toChar).mkString
                Asn1String(value)
              case 0x0D ⇒ //Relative OID
                Asn1RelativeOID(iter.getBytes(length))
              case 0x0E | 0x0F ⇒ //WTF? These are reserved
                //TODO check this
                val value = iter.getBytes(length).map(_.toChar).mkString
                println(s"Unhandled classTag 0x${classTag.toHexString}, with possible value '${value}', these are reserved values and it should not have gotten them")
                Asn1Null
              case 0x10 ⇒
                Asn1Sequence(loop(iter.getByteString(length), List()): _*)
              case 0x11 ⇒
                Asn1Set(loop(iter.getByteString(length), List()): _*)
              case 0x12 ⇒ //NumericString
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x13 ⇒ //PrintableString
                val value = iter.getBytes(length).map(_.toChar).mkString
                Asn1String(value)
              case 0x14 ⇒ //T61String
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x15 ⇒ //VideotexString
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x16 ⇒ //IA5String
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x17 ⇒ //UTCTime
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x18 ⇒ //GeneralizedTime
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x19 ⇒ //GraphicString
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1A ⇒ //VisibleString
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1B ⇒ //GeneralString
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1C ⇒ //UniversalString
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1D ⇒ //CHARACTER STRING
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1E ⇒ //BMPString
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")
              case 0x1F ⇒ //Use long form
                //TODO write this
                throw new Error(s"Unhandled classTag 0x${classTag.toHexString}")

              case _ ⇒ throw new Error(s"Unkown classTag 0x${classTag.toHexString}")
            }
        }
        (res, iter.toByteString)
      } catch {
        case e: NoSuchElementException ⇒
          println("0x" + str.map(_.toInt.toHexString).mkString(", 0x"))
          throw e
      }

    }

    val result = loop(str, List.empty)
    result
  }
}
