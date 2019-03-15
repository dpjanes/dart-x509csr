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
import 'dart:typed_data';

import "package:pointycastle/export.dart";
import 'package:asn1lib/asn1lib.dart';

import "./crypto.dart";

ASN1Object _encodeDN(Map<String, String> d) {
  var DN = ASN1Sequence();

  d.forEach((name, value) {
    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.fromName(name);
    if (oid == null) {
      print("x509csr.makeDN: name=${name} not found");
      return;
    }

    ASN1Object ovalue;

    switch (name.toUpperCase()) {
      case "C":
        {
          ovalue = ASN1PrintableString(value);
        }
        break;
      case "CN":
      case "O":
      case "L":
      case "S":
      default:
        {
          ovalue = ASN1UTF8String(value);
        }
        break;
    }

    if (ovalue == null) {
      print("x509csr.makeDN: value=${value} not processed");
      return;
    }

    var pair = ASN1Sequence();
    pair.add(oid);
    pair.add(ovalue);

    var pairset = ASN1Set();
    pairset.add(pair);

    DN.add(pairset);
  });

  return DN;
}
/*
 */
ASN1Sequence _makePublicKeyBlock(RSAPublicKey publicKey) {
  ASN1Sequence blockEncryptionType = ASN1Sequence();
  blockEncryptionType.add(ASN1ObjectIdentifier.fromName("rsaEncryption"));
  blockEncryptionType.add(ASN1Null());

  ASN1Sequence publicKeySequence = ASN1Sequence();
  publicKeySequence.add(ASN1Integer(publicKey.modulus));
  publicKeySequence.add(ASN1Integer(publicKey.exponent));

  ASN1BitString blockPublicKey = ASN1BitString(publicKeySequence.encodedBytes);

  ASN1Sequence outer = ASN1Sequence();
  outer.add(blockEncryptionType);
  outer.add(blockPublicKey);

  return outer;

}

/*
 */
ASN1Object makeRSACSR(
    Map dn, RSAPrivateKey privateKey, RSAPublicKey publicKey) {
  ASN1Object encodedDN = _encodeDN(dn);


  ASN1Sequence blockDN = ASN1Sequence();
  blockDN.add(ASN1Integer(BigInt.from(0)));
  blockDN.add(encodedDN);
  blockDN.add(_makePublicKeyBlock(publicKey));
  blockDN.add(ASN1Object.fromBytes(
      Uint8List.fromList([0xA0, 0x00]))); // let's call this WTF

  ASN1Sequence blockProtocol = ASN1Sequence();
  blockProtocol.add(ASN1ObjectIdentifier.fromName("md5WithRSAEncryption"));
  blockProtocol.add(ASN1Null());

  ASN1Sequence outer = ASN1Sequence();
  outer.add(blockDN);
  outer.add(blockProtocol);
  outer.add(ASN1BitString(rsaPrivateKeyToBytes(privateKey)));
  return outer;
}

main(List<String> arguments) {
  AsymmetricKeyPair keyPair = rsaGenerateKeyPair();

  ASN1ObjectIdentifier.registerFrequentNames();
  Map<String,String> dn = {
    "CN": "www.davidjanes.com",
    "O": "Consensas",
    "L": "Toronto",
    "ST": "Ontario",
    "C": "CA",
  };

  ASN1Object encodedCSR = makeRSACSR(dn, keyPair.privateKey, keyPair.publicKey);

  print(base64.encode(encodedCSR.encodedBytes));
}
