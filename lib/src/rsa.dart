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
import "./ids.dart";
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
  AsymmetricKeyPair keyPair = rsaGenerateKeyPair();

  ASN1Object DN = makeDN({
    "CN": "www.davidjanes.com",
    "O": "Consensas",
    "L": "Toronto",
    "ST": "Ontario",
    "C": "CA",
  });

  ASN1Sequence blockDN = ASN1Sequence();
  blockDN.add(ASN1Integer(BigInt.from(0)));
  blockDN.add(DN);
  blockDN.add(makeDNSignature(rsaSign(DN.encodedBytes, keyPair.privateKey)));

  ASN1Sequence blockProtocol = ASN1Sequence();
  blockProtocol.add(lookupX500ObjectIdentifier("md5WithRSAEncryption"));

  RSAPublicKey publicKey = keyPair.publicKey;
  var publicKeySeq = new ASN1Sequence();
  publicKeySeq.add(ASN1Integer(publicKey.modulus));
  publicKeySeq.add(ASN1Integer(publicKey.exponent));
  var publicKeySeqBitString =
      new ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

  ASN1Sequence outer = ASN1Sequence();
  outer.add(blockDN);
  outer.add(blockProtocol);
  outer.add(ASN1BitString(rsaPublicKeyToBytes(publicKey)));

  print(base64.encode(outer.encodedBytes));

  // print(signedDN.bytes);
}
