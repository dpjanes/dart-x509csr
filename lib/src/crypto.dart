/*
 *  providers/crypto.dart
 *
 *  David Janes
 *  Consensas
 *  2019-02-24
 */

import "package:pointycastle/export.dart";
import "package:asn1lib/asn1lib.dart";

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/*
 */
AsymmetricKeyPair rsaGenerateKeyPair({int size = 2048}) {
  var keyParams =
      new RSAKeyGeneratorParameters(BigInt.parse('65537'), size, 12);

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
Uint8List bigIntnToBytes(BigInt n) {
  int bytes = (n.bitLength + 7) >> 3;

  var b256 = new BigInt.from(256);
  var result = new Uint8List(bytes);

  for (int i = 0; i < bytes; i++) {
    result[i] = n.remainder(b256).toInt();
    n = n >> 8;
  }

  return result;
}

Uint8List rsaPublicKeyModulusToBytes(RSAPublicKey publicKey) => bigIntnToBytes(publicKey.modulus);
Uint8List rsaPublicKeyExponentToBytes(RSAPublicKey publicKey) => bigIntnToBytes(publicKey.exponent);
Uint8List rsaPrivateKeyToBytes(RSAPrivateKey privateKey) => bigIntnToBytes(privateKey.modulus);

/*
 */
class CryptoProvider {
  static final CryptoProvider instance = CryptoProvider._private();
  CryptoProvider._private();

  factory CryptoProvider() {
    return instance;
  }

  Future<void> initialize() async {}

  void createCSR() {
    print("A.1");
    AsymmetricKeyPair keyPair = generateKeyPair();
    print("A.2");

    print(encodePublicKeyToPem(keyPair.publicKey));
    print(encodePrivateKeyToPem(keyPair.privateKey));

    /*
var keyParams = new RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 5);

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

  var keyPair = k.generateKeyPair();

  print(new RsaKeyHelper().encodePublicKeyToPem(keyPair.publicKey) );
  print(new RsaKeyHelper().encodePrivateKeyToPem(keyPair.privateKey) );
  */
  }

// https://gist.github.com/proteye/982d9991922276ccfb011dfc55443d74
  static AsymmetricKeyPair generateKeyPair() {
    var keyParams =
        new RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12);

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

  String encrypt(String plaintext, RSAPublicKey publicKey) {
    var cipher = new RSAEngine()
      ..init(true, new PublicKeyParameter<RSAPublicKey>(publicKey));
    var cipherText =
        cipher.process(new Uint8List.fromList(plaintext.codeUnits));

    return new String.fromCharCodes(cipherText);
  }

  String decrypt(String ciphertext, RSAPrivateKey privateKey) {
    var cipher = new RSAEngine()
      ..init(false, new PrivateKeyParameter<RSAPrivateKey>(privateKey));
    var decrypted =
        cipher.process(new Uint8List.fromList(ciphertext.codeUnits));

    return new String.fromCharCodes(decrypted);
  }

/*
  parsePublicKeyFromPem(pemString) {
    List<int> publicKeyDER = decodePEM(pemString);
    var asn1Parser = new ASN1Parser(publicKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var publicKeyBitString = topLevelSeq.elements[1];

    var publicKeyAsn = new ASN1Parser(publicKeyBitString.contentBytes());
    ASN1Sequence publicKeySeq = publicKeyAsn.nextObject();
    var modulus = publicKeySeq.elements[0] as ASN1Integer;
    var exponent = publicKeySeq.elements[1] as ASN1Integer;

    RSAPublicKey rsaPublicKey = RSAPublicKey(
      modulus.valueAsBigInteger,
      exponent.valueAsBigInteger
    );

    return rsaPublicKey;
  }
  */

  /*

  parsePrivateKeyFromPem(pemString) {
    List<int> privateKeyDER = decodePEM(pemString);
    var asn1Parser = new ASN1Parser(privateKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var version = topLevelSeq.elements[0];
    var algorithm = topLevelSeq.elements[1];
    var privateKey = topLevelSeq.elements[2];

    asn1Parser = new ASN1Parser(privateKey.contentBytes());
    var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    version = pkSeq.elements[0];
    var modulus = pkSeq.elements[1] as ASN1Integer;
    var publicExponent = pkSeq.elements[2] as ASN1Integer;
    var privateExponent = pkSeq.elements[3] as ASN1Integer;
    var p = pkSeq.elements[4] as ASN1Integer;
    var q = pkSeq.elements[5] as ASN1Integer;
    var exp1 = pkSeq.elements[6] as ASN1Integer;
    var exp2 = pkSeq.elements[7] as ASN1Integer;
    var co = pkSeq.elements[8] as ASN1Integer;

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
      modulus.valueAsBigInteger,
      privateExponent.valueAsBigInteger,
      p.valueAsBigInteger,
      q.valueAsBigInteger
    );

    return rsaPrivateKey;
  }
  
*/
  encodePublicKeyToPem(RSAPublicKey publicKey) {
    var algorithmSeq = new ASN1Sequence();
    var algorithmAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    var paramsAsn1Obj =
        new ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
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

    return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
  }

  encodePrivateKeyToPem(RSAPrivateKey privateKey) {
    var version = ASN1Integer(BigInt.from(0));

    var algorithmSeq = new ASN1Sequence();
    var algorithmAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    var paramsAsn1Obj =
        new ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
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

    return """-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----""";
  }
}
