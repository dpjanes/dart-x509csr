/*
 *  lib/crypto.dart
 *
 *  David Janes
 *  Consensas
 *  2019-03-15
 */

import "package:pointycastle/export.dart";
import "package:asn1lib/asn1lib.dart";

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/*
 */
AsymmetricKeyPair rsaGenerateKeyPair({int chunkSize = 2048}) {
  var keyParams =
      new RSAKeyGeneratorParameters(BigInt.parse('65537'), chunkSize, 12);

  var secureRandom = new FortunaRandom();
  var random = new Random.secure();
  List<int> seeds = [];
  for (int i = 0; i < 32; i++) {
    seeds.add(random.nextInt(255));
  }
  secureRandom.seed(new KeyParameter(new Uint8List.fromList(seeds)));

  var rngParams = new ParametersWithRandom(keyParams, secureRandom);
  var k = new RSAKeyGenerator();
  k.init(rngParams);

  return k.generateKeyPair();
}

/*
 */
Uint8List rsaSign(Uint8List inBytes, RSAPrivateKey privateKey) {
  Signer signer = new Signer("SHA-1/RSA");
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));

  RSASignature signature = signer.generateSignature(inBytes);

  return signature.bytes;
}

/*
https://github.com/dart-lang/sdk/issues/32803#issuecomment-387405784
 */
Uint8List _bigIntToBytes(BigInt n) {
  int bytes = (n.bitLength + 7) >> 3;

  var b256 = new BigInt.from(256);
  var result = new Uint8List(bytes);

  for (int i = 0; i < bytes; i++) {
    result[i] = n.remainder(b256).toInt();
    n = n >> 8;
  }

  return result;
}

Uint8List rsaPublicKeyModulusToBytes(RSAPublicKey publicKey) =>
    _bigIntToBytes(publicKey.modulus);
Uint8List rsaPublicKeyExponentToBytes(RSAPublicKey publicKey) =>
    _bigIntToBytes(publicKey.exponent);
Uint8List rsaPrivateKeyToBytes(RSAPrivateKey privateKey) =>
    _bigIntToBytes(privateKey.modulus);

List<String> _chunked(String encoded, {chunkSize = 64}) {
  List<String> chunks = [];

  for (int i = 0; i < encoded.length; i += chunkSize) {
    int end = (i + chunkSize < encoded.length) ? i + chunkSize : encoded.length;
    chunks.add(encoded.substring(i, end));
  }

  return chunks;
}

encodeCSRToPem(ASN1Object csr) {
  List<String> chunks = _chunked(base64.encode(csr.encodedBytes));

  return "-----BEGIN CERTIFICATE REQUEST-----\r\n" +
      chunks.join("\r\n") +
      "\r\n-----END CERTIFICATE REQUEST-----\r\n";
}

// from https://gist.github.com/proteye/982d9991922276ccfb011dfc55443d74
encodeRSAPublicKeyToPem(RSAPublicKey publicKey) {
  var algorithmSeq = new ASN1Sequence();
  var algorithmAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList(
      [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
  var paramsAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  var publicKeySeq = new ASN1Sequence();
  publicKeySeq.add(ASN1Integer(publicKey.modulus));
  publicKeySeq.add(ASN1Integer(publicKey.exponent));
  var publicKeySeqBitString =
      new ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

  var topLevelSeq = new ASN1Sequence();
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqBitString);
  var dataBase64 = base64.encode(topLevelSeq.encodedBytes);
  List<String> chunks = _chunked(dataBase64);

  return """-----BEGIN PUBLIC KEY-----\r\n${chunks.join("\r\n")}\r\n-----END PUBLIC KEY-----\r\n""";
}

encodeRSAPrivateKeyToPem(RSAPrivateKey privateKey) {
  var version = ASN1Integer(BigInt.from(0));

  var algorithmSeq = new ASN1Sequence();
  var algorithmAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList(
      [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
  var paramsAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  var privateKeySeq = new ASN1Sequence();
  var modulus = ASN1Integer(privateKey.n);
  var publicExponent = ASN1Integer(BigInt.parse('65537'));
  var privateExponent = ASN1Integer(privateKey.d);
  var p = ASN1Integer(privateKey.p);
  var q = ASN1Integer(privateKey.q);
  var dP = privateKey.d % (privateKey.p - BigInt.from(1));
  var exp1 = ASN1Integer(dP);
  var dQ = privateKey.d % (privateKey.q - BigInt.from(1));
  var exp2 = ASN1Integer(dQ);
  var iQ = privateKey.q.modInverse(privateKey.p);
  var co = ASN1Integer(iQ);

  privateKeySeq.add(version);
  privateKeySeq.add(modulus);
  privateKeySeq.add(publicExponent);
  privateKeySeq.add(privateExponent);
  privateKeySeq.add(p);
  privateKeySeq.add(q);
  privateKeySeq.add(exp1);
  privateKeySeq.add(exp2);
  privateKeySeq.add(co);
  var publicKeySeqOctetString =
      new ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

  var topLevelSeq = new ASN1Sequence();
  topLevelSeq.add(version);
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqOctetString);
  var dataBase64 = base64.encode(topLevelSeq.encodedBytes);

  List<String> chunks = _chunked(dataBase64);

  return """-----BEGIN PRIVATE KEY-----\r\n${chunks.join("\r\n")}\r\n-----END PRIVATE KEY-----\r\n""";
}
