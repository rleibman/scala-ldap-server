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

import org.scalatest.FlatSpec
import akka.util.ByteStringBuilder
import akka.util.ByteString

class BEREncoderSpec extends FlatSpec {
  "decoding and encoding an empty byte array" should "reteurn the same thing" in {
    val data = (new ByteStringBuilder).result()
    val decoded = BEREncoder.decode(data)
    assert(decoded.isEmpty)
    decoded.map { one =>
      val encoded = BEREncoder.encode(one)
      assert(data === encoded)
    }
  }
  "encoding and decoding an empty Sequence" should "return the same thing" in {
    val asn1 = Asn1Sequence()
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    println(encoded.map(_.formatted("%02X").takeRight(2)).mkString(" "))
    assert(asn1 === decoded(0))
  }
  "encoding and decoding an simple Sequence 1" should "return the same thing" in {
    val asn1 = Asn1Sequence(Asn1Short(0x1234.toShort))
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    println(encoded.map(_.formatted("%02X").takeRight(2)).mkString(" "))
    assert(asn1 === decoded(0))
  }
  "encoding and decoding a Short" should "return the same thing" in {
    val asn1 = Asn1Short(123.toShort)
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    println(encoded.map(_.formatted("%02X").takeRight(2)).mkString(" "))
    assert(asn1 === decoded(0))
  }
  "encoding and decoding a Byte" should "return the same thing" in {
    val asn1 = Asn1Byte(12.toByte)
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    println(encoded.map(_.formatted("%02X").takeRight(2)).mkString(" "))
    assert(asn1 === decoded(0))
  }
  "encoding and decoding an int" should "return the same thing" in {
    val asn1 = Asn1Int(123)
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    println(encoded.map(_.formatted("%02X").takeRight(2)).mkString(" "))
    assert(asn1 === decoded(0))
  }
  "encoding an empty Application" should "return the same thing" in {
    val asn1 = Asn1Application(12)
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    println(encoded.map(_.formatted("%02X").takeRight(2)).mkString(" "))
    assert(asn1 === decoded(0))
  }
  "encoding a simple Application 1" should "return the same thing" in {
    val asn1 = Asn1Application(12, Asn1Short(0x4321.toShort))
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    println(encoded.map(_.formatted("%02X").takeRight(2)).mkString(" "))
    assert(asn1 === decoded(0))
  }
  "encoding and decoding a simple Sequence 2" should "return the same thing" in {
    val asn1 = Asn1Sequence(Asn1Short(1.toShort), Asn1Application(12))
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    assert(asn1 === decoded(0))
  }
  "encoding and decoding a simple Sequence 3" should "return the same thing" in {
    val asn1 = Asn1Sequence(Asn1Application(12))
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    assert(asn1 === decoded(0))
  }
  "encoding and decoding an empty context specific" should "return the same thing" in {
    val asn1 = Asn1ContextSpecific(3, Array())
    val encoded = BEREncoder.encode(asn1)
    val decoded = BEREncoder.decode(encoded)
    assert(asn1 === decoded(0))
  }
  "decoding and encoding a sequence" should "return the same thing" in {
    val bytes: Array[Byte] = Array(0x30, 0x33, 0x2, 0x1, 0x1, 0x60, 0x2e, 0x2, 0x1, 0x3, 0x4, 0x1f, 0x63, 0x6e, 0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d, 0x67, 0x6c, 0x75, 0x65, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, 0x80.toByte, 0x8, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64)
    val bb = new ByteStringBuilder()
    bb.putBytes(bytes)
    val data = bb.result()
    val decoded = BEREncoder.decode(data)
    val encoded = BEREncoder.encode(decoded(0))
    val inStr = data.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    val outStr = encoded.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    println("in  = " + inStr)
    println("out = " + outStr)
    val decoded2 = BEREncoder.decode(data)
    println(decoded)
    println(decoded2)
    assert(inStr === outStr)
    val encoded2 = BEREncoder.encode(decoded2(0))
    assert(decoded === decoded2)
    assert(data === encoded)
  }
  //  Broken
  "decoding and encoding a sequence 3" should "return the same thing" in {
    val bytes = Array[Int](0x30, 0x6, 0x2, 0x1, 0x3, 0x50, 0x1, 0x2).map(_.toByte)
    val bb = new ByteStringBuilder()
    bb.putBytes(bytes)
    val data = bb.result()
    val decoded = BEREncoder.decode(data)
    val encoded = BEREncoder.encode(decoded(0))
    val inStr = data.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    val outStr = encoded.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    println("in  = " + inStr)
    println("out = " + outStr)
    val decoded2 = BEREncoder.decode(data)
    println(decoded)
    println(decoded2)
    assert(inStr === outStr)
    val encoded2 = BEREncoder.encode(decoded2(0))
    assert(decoded === decoded2)
    assert(data === encoded)
  }
  "decoding and encoding a sequence 2" should "return the same thing" in {
    val bytes = Array[Int](0x30, 0x81, 0xdd, 0x2, 0x1, 0x2, 0x63, 0x81, 0xd7, 0x4, 0x0, 0xa, 0x1, 0x0, 0xa, 0x1, 0x0, 0x2, 0x1, 0x0, 0x2, 0x1, 0x0, 0x1, 0x1, 0x0, 0x87, 0xb, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x81, 0xb6, 0x4, 0xe, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x73, 0x4, 0x11, 0x73, 0x75, 0x62, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x53, 0x75, 0x62, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x4, 0x14, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x4c, 0x44, 0x41, 0x50, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x4, 0x17, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x53, 0x41, 0x53, 0x4c, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x73, 0x6d, 0x73, 0x4, 0x12, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x4, 0x10, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x4, 0x11, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x4, 0xa, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x4, 0xd, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x4, 0x1, 0x2b, 0x4, 0xb, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73).map(_.toByte)
    val bb = new ByteStringBuilder()
    bb.putBytes(bytes)
    val data = bb.result()
    val decoded = BEREncoder.decode(data)

    val encoded = BEREncoder.encode(decoded(0))
    val inStr = data.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    val outStr = encoded.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    println("in  = " + inStr)
    println("out = " + outStr)
    val decoded2 = BEREncoder.decode(data)
    println(decoded)
    println(decoded2)
    assert(inStr === outStr)
    val encoded2 = BEREncoder.encode(decoded2(0))
    assert(decoded === decoded2)
    assert(data === encoded)
  }

  "decoding and encoding a sequence 4" should "return the same thing" in {
    val bytes = "3038020102633304000a01000a0103020100020100010100870b6f626a656374436c61737330130411737562736368656d61537562656e747279".grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
    val bb = new ByteStringBuilder()
    bb.putBytes(bytes)
    val data = bb.result()
    val decoded = BEREncoder.decode(data)

    val encoded = BEREncoder.encode(decoded(0))
    val inStr = data.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    val outStr = encoded.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    println("in  = " + inStr)
    println("out = " + outStr)
    val decoded2 = BEREncoder.decode(data)
    println(decoded)
    println(decoded2)
    assert(inStr === outStr)
    val encoded2 = BEREncoder.encode(decoded2(0))
    assert(decoded === decoded2)
    assert(data === encoded)
  }
  //TODO this one is still broken
  "decoding and encoding a sequence 5" should "return the same thing" in {
    val bytes = "3081dd0201026381d704000a01000a0100020100020100010100870b6f626a656374436c6173733081b6040e6e616d696e67436f6e74657874730411737562736368656d61537562656e7472790414737570706f727465644c44415056657273696f6e0417737570706f727465645341534c4d656368616e69736d730412737570706f72746564457874656e73696f6e0410737570706f72746564436f6e74726f6c0411737570706f727465644665617475726573040a76656e646f724e616d65040d76656e646f7256657273696f6e04012b040b6f626a656374436c617373".grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
    val bb = new ByteStringBuilder()
    bb.putBytes(bytes)
    val data = bb.result()
    val decoded = BEREncoder.decode(data)

    val encoded = BEREncoder.encode(decoded(0))
    val inStr = data.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    val outStr = encoded.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    println("in  = " + inStr)
    println("out = " + outStr)
    val decoded2 = BEREncoder.decode(data)
    println(decoded)
    println(decoded2)
    assert(inStr === outStr)
    val encoded2 = BEREncoder.encode(decoded2(0))
    assert(decoded === decoded2)
    assert(data === encoded)
  }
  "decoding and encoding a sequence 6" should "return the same thing" in {
    val bytes = "3028020102632304000a01000a0100020100020100010100870b6f626a656374436c617373300304012a".grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
    val bb = new ByteStringBuilder()
    bb.putBytes(bytes)
    val data = bb.result()
    val decoded = BEREncoder.decode(data)

    val encoded = BEREncoder.encode(decoded(0))
    val inStr = data.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    val outStr = encoded.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    println("in  = " + inStr)
    println("out = " + outStr)
    val decoded2 = BEREncoder.decode(data)
    println(decoded)
    println(decoded2)
    assert(inStr === outStr)
    val encoded2 = BEREncoder.encode(decoded2(0))
    assert(decoded === decoded2)
    assert(data === encoded)
  }
  "decoding and encoding a sequence 7" should "return the same thing" in {
    val bytes = "3032020102632d04000a01010a0100020100020100010100870b6f626a656374436c617373300d040b6f626a656374436c617373".grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
    val bb = new ByteStringBuilder()
    bb.putBytes(bytes)
    val data = bb.result()
    val decoded = BEREncoder.decode(data)

    val encoded = BEREncoder.encode(decoded(0))
    val inStr = data.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    val outStr = encoded.map(_.formatted("%02X").takeRight(2)).mkString(" ")
    println("in  = " + inStr)
    println("out = " + outStr)
    val decoded2 = BEREncoder.decode(data)
    println(decoded)
    println(decoded2)
    assert(inStr === outStr)
    val encoded2 = BEREncoder.encode(decoded2(0))
    assert(decoded === decoded2)
    assert(data === encoded)
  }

  "Data with two messages wrapped " should "Return two messages" in {
    val data = ByteString(48, 24, 2, 1, 1, 100, 19, 4, 17, 100, 99, 61, 101, 120, 97, 109, 112, 108, 101, 44, 100, 99, 61, 99, 111, 109, 48, 50, 2, 1, 1, 101, 45, 10, 4, 0, 0, 0, 0, 4, 0, 4, 35, 83, 101, 97, 114, 99, 104, 32, 115, 117, 99, 99, 101, 115, 115, 102, 117, 108, 44, 32, 111, 110, 101, 32, 114, 101, 115, 117, 108, 116, 32, 102, 111, 117, 110, 100)
    val decoded = BEREncoder.decode(data)
    assert(decoded.size === 2)
  }
}
