/*
 *  example/x509csr.dart
 *
 *  David Janes
 *  Consensas
 *  2019-02-24
 */
import 'package:x509csr/x509csr.dart';

import "package:pointycastle/export.dart";
import 'package:asn1lib/asn1lib.dart';

main(List<String> arguments) {
  AsymmetricKeyPair keyPair = rsaGenerateKeyPair();

  ASN1ObjectIdentifier.registerFrequentNames();
  Map<String, String> dn = {
    "CN": "www.davidjanes.com",
    "O": "Consensas",
    "L": "Toronto",
    "ST": "Ontario",
    "C": "CA",
  };

  ASN1Object encodedCSR = makeRSACSR(dn, keyPair.privateKey, keyPair.publicKey);

  print(encodeCSRToPem(encodedCSR));
  print(encodeRSAPublicKeyToPem(keyPair.publicKey));
  print(encodeRSAPrivateKeyToPem(keyPair.privateKey));
}
