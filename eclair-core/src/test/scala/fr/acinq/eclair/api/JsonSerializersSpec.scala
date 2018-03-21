/*
 * Copyright 2018 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.api

import fr.acinq.bitcoin.{BinaryData, OutPoint}
import org.json4s.Formats
import org.json4s.jackson.Serialization
import org.scalatest.FunSuite

class JsonSerializersSpec extends FunSuite {

  def writeRead(map: Map[OutPoint, BinaryData])(implicit formats: Formats) = {
    val ser = Serialization.write(map)
    val check = Serialization.read[Map[OutPoint, BinaryData]](ser)
    assert(check === map)
  }

  test("deserialize Map[OutPoint, BinaryData]") {
    val map = Map(
      OutPoint("11418a2d282a40461966e4f578e1fdf633ad15c1b7fb3e771d14361127233be1", 0) -> BinaryData("dead"),
      OutPoint("3d62bd4f71dc63798418e59efbc7532380c900b5e79db3a5521374b161dd0e33", 1) -> BinaryData("beef")
    )
    implicit val formats = org.json4s.DefaultFormats

    // it won't work without a custom key serializer
    val error = intercept[org.json4s.MappingException] {
      writeRead(map)(formats)
    }
    assert(error.msg.contains("Do not know how to serialize key of type class fr.acinq.bitcoin.OutPoint."))

    // but it works with our custom key serializer
    implicit val formats1 = formats + new OutPointKeySerializer
    writeRead(map)(formats1)
  }
}
