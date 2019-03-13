/*
 * lib/src/rsa.dart
 *
 * David Janes
 * 2018-03-13
 *
 * Copyright [2019] David P. Janes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import "package:pointycastle/export.dart";
import 'package:asn1lib/asn1lib.dart';

import "./dn.dart";
import "./crypto.dart";

/*
 */
String generateRSACSR({Map dn}) {
  ASN1Object DN = makeDN({
    "CN": "www.davidjanes.com",
    "O": "Consensas",
    "L": "Toronto",
    "ST": "Ontario",
    "C": "CA",
  });

  ASN1Sequence inner = ASN1Sequence();
  // inner.add(ASN1Integer(BigInt.from(0)));
  // inner.add(DN);
  // inner.add(ASN1Null());

  return base64.encode(inner.encodedBytes);
}

main(List<String> arguments) {
  String csr = generateRSACSR(dn: {
    "CN": "www.davidjanes.com",
    "O": "Consensas",
    "L": "Toronto",
    "S": "Ontario",
    "C": "CA",
  });

  ASN1Object DN = makeDN({
    "CN": "www.davidjanes.com",
    "O": "Consensas",
    "L": "Toronto",
    "ST": "Ontario",
    "C": "CA",
  });
  
  AsymmetricKeyPair keyPair = rsaGenerateKeyPair();

  Uint8List signedDN =rsaSign(DN.encodedBytes, keyPair.privateKey);

  ASN1Sequence inner = ASN1Sequence();
  inner.add(ASN1Integer(BigInt.from(0)));
  inner.add(DN);
  inner.add(ASN1BitString(signedDN));
  // inner.add(ASN1Null());

  print( base64.encode(inner.encodedBytes));

  // print(signedDN.bytes);
}
