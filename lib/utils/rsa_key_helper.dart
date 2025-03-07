import 'dart:convert';
import 'dart:math';

import "package:asn1lib/asn1lib.dart";
import 'package:flutter/foundation.dart';
import "package:pointycastle/export.dart";

class RsaKeyHelper {
  // RSA 키 쌍을 생성하는 비동기 메서드
  static Future<AsymmetricKeyPair<PublicKey, PrivateKey>>
  computeRSAKeyPair() async {
    return await compute(_getRsaKeyPair, _getSecureRandom());
  }

  // 공개 키로 평문을 암호화하는 메서드
  static String encryptWithPublicKey(String plainText, RSAPublicKey publicKey) {
    final encrypter = OAEPEncoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

    final plainTextBytes = utf8.encode(plainText);
    final encryptedBytes =
    encrypter.process(Uint8List.fromList(plainTextBytes));

    return base64Encode(encryptedBytes);
  }

  // 개인 키로 암호문을 복호화하는 메서드
  static String decryptWithPrivateKey(
      String encryptedText, RSAPrivateKey privateKey) {
    final decrypter = OAEPEncoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

    final encryptedBytes = base64Decode(encryptedText);
    final decryptedBytes =
    decrypter.process(Uint8List.fromList(encryptedBytes));

    return utf8.decode(decryptedBytes);
  }

  // Private Key를 PEM 형식으로 인코딩하는 메서드
  static String encodePrivateKeyToPemPKCS1(RSAPrivateKey privateKey) {
    var topLevel = ASN1Sequence();

    var version = ASN1Integer(BigInt.from(0));
    var modulus = ASN1Integer(privateKey.n!);
    var publicExponent = ASN1Integer(privateKey.exponent!);
    var privateExponent = ASN1Integer(privateKey.d!);
    var p = ASN1Integer(privateKey.p!);
    var q = ASN1Integer(privateKey.q!);
    var dP = privateKey.d! % (privateKey.p! - BigInt.from(1));
    var exp1 = ASN1Integer(dP);
    var dQ = privateKey.d! % (privateKey.q! - BigInt.from(1));
    var exp2 = ASN1Integer(dQ);
    var iQ = privateKey.q!.modInverse(privateKey.p!);
    var co = ASN1Integer(iQ);

    topLevel.add(version);
    topLevel.add(modulus);
    topLevel.add(publicExponent);
    topLevel.add(privateExponent);
    topLevel.add(p);
    topLevel.add(q);
    topLevel.add(exp1);
    topLevel.add(exp2);
    topLevel.add(co);

    var dataBase64 = base64.encode(topLevel.encodedBytes);

    return """-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----""";
  }

  // Public Key를 PEM 형식으로 인코딩하는 메서드
  static String encodePublicKeyToPemPKCS1(RSAPublicKey publicKey) {
    var topLevel = new ASN1Sequence();

    topLevel.add(ASN1Integer(publicKey.modulus!));
    topLevel.add(ASN1Integer(publicKey.exponent!));

    var dataBase64 = base64.encode(topLevel.encodedBytes);
    return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
  }

  // PEM 형식의 문자열을 Public Key로 변환하는 메서드
  static RSAPublicKey parsePublicKeyFromPem(pemString) {
    List<int> publicKeyDER = _decodePEM(pemString);
    var asn1Parser = ASN1Parser(Uint8List.fromList(publicKeyDER));
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    ASN1Integer modulus, exponent;
    // Depending on the first element type, we either have PKCS1 or 2
    if (topLevelSeq.elements[0].runtimeType == ASN1Integer) {
      modulus = topLevelSeq.elements[0] as ASN1Integer;
      exponent = topLevelSeq.elements[1] as ASN1Integer;
    } else {
      var publicKeyBitString = topLevelSeq.elements[1];

      var publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
      ASN1Sequence publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
      modulus = publicKeySeq.elements[0] as ASN1Integer;
      exponent = publicKeySeq.elements[1] as ASN1Integer;
    }

    RSAPublicKey rsaPublicKey =
    RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);

    return rsaPublicKey;
  }

  // PEM 형식의 문자열을 Private Key로 변환하는 메서드
  static RSAPrivateKey parsePrivateKeyFromPem(pemString) {
    List<int> privateKeyDER = _decodePEM(pemString);
    var asn1Parser = ASN1Parser(Uint8List.fromList(privateKeyDER));
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus, privateExponent, p, q;
    // Depending on the number of elements, we will either use PKCS1 or PKCS8
    if (topLevelSeq.elements.length == 3) {
      var privateKey = topLevelSeq.elements[2];

      asn1Parser = ASN1Parser(privateKey.contentBytes());
      var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

      modulus = pkSeq.elements[1] as ASN1Integer;
      privateExponent = pkSeq.elements[3] as ASN1Integer;
      p = pkSeq.elements[4] as ASN1Integer;
      q = pkSeq.elements[5] as ASN1Integer;
    } else {
      modulus = topLevelSeq.elements[1] as ASN1Integer;
      privateExponent = topLevelSeq.elements[3] as ASN1Integer;
      p = topLevelSeq.elements[4] as ASN1Integer;
      q = topLevelSeq.elements[5] as ASN1Integer;
    }

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
        modulus.valueAsBigInteger,
        privateExponent.valueAsBigInteger,
        p.valueAsBigInteger,
        q.valueAsBigInteger);

    return rsaPrivateKey;
  }

  // 텍스트를 Private Key로 서명하는 메서드
  static String sign(String plainText, RSAPrivateKey privateKey) {
    var signer = RSASigner(SHA256Digest(), "0609608648016503040201");
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    return base64Encode(
        signer.generateSignature(_createUint8ListFromString(plainText)).bytes);
  }

  // 문자열을 Uint8List로 변환하는 메서드
  static Uint8List _createUint8ListFromString(String s) {
    var codec = const Utf8Codec(allowMalformed: true);
    return Uint8List.fromList(codec.encode(s));
  }

  // PEM 형식의 문자열을 디코딩하는 헬퍼 메서드
  static List<int> _decodePEM(String pem) {
    return base64.decode(_removePemHeaderAndFooter(pem));
  }

  // PEM 형식의 문자열에서 헤더와 푸터를 제거하는 메서드
  static String _removePemHeaderAndFooter(String pem) {
    var startsWith = [
      "-----BEGIN PUBLIC KEY-----",
      "-----BEGIN PRIVATE KEY-----"
    ];
    var endsWith = [
      "-----END PUBLIC KEY-----",
      "-----END PRIVATE KEY-----"
    ];

    pem = pem.replaceAll(' ', '');
    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('\r', '');

    for (var s in startsWith) {
      s = s.replaceAll(' ', '');
      if (pem.startsWith(s)) {
        pem = pem.substring(s.length);
      }
    }

    for (var s in endsWith) {
      s = s.replaceAll(' ', '');
      if (pem.endsWith(s)) {
        pem = pem.substring(0, pem.length - s.length);
      }
    }

    return pem;
  }

  // RSA 키 쌍을 생성하는 헬퍼 메서드
  static AsymmetricKeyPair<PublicKey, PrivateKey> _getRsaKeyPair(
      SecureRandom secureRandom) {
    var rsapars = RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 5);
    var params = ParametersWithRandom(rsapars, secureRandom);
    var keyGenerator = RSAKeyGenerator();
    keyGenerator.init(params);
    return keyGenerator.generateKeyPair();
  }

  // SecureRandom 인스턴스를 생성하는  메서드
  static SecureRandom _getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }
}