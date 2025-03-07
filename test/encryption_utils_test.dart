import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_wataru/utils/aes_key_helper.dart';
import 'package:flutter_wataru/utils/rsa_key_helper.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() {

  group('AES, RSA 테스트', () {
    test('AES 암호화 복호화 테스트', () {
      final String originalText = '안녕하세요';
      final String encryptedText = AesKeyHelper.encryptAES(originalText);
      final String decryptedText = AesKeyHelper.decryptAES(encryptedText);

      print('AES 암호화된 텍스트: $encryptedText');
      print('AES 복호화된 텍스트: $decryptedText');

      expect(decryptedText, equals(originalText));
    });

    test('RSA 암호화 복호화 테스트', () async {
      final String originalText = '안녕하세요';
      final AsymmetricKeyPair<PublicKey, PrivateKey> keyPair = await RsaKeyHelper.computeRSAKeyPair();
      final String encryptedText = RsaKeyHelper.encryptWithPublicKey(originalText, keyPair.publicKey as RSAPublicKey);
      final String decryptedText = RsaKeyHelper.decryptWithPrivateKey(encryptedText, keyPair.privateKey as RSAPrivateKey);

      print('RSA 암호화된 텍스트: $encryptedText');
      print('RSA 복호화된 텍스트: $decryptedText');

      expect(decryptedText, equals(originalText));
    });
  });
}