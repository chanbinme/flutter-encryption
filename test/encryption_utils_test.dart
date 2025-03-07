import 'package:flutter_encryption/utils/aes_key_helper.dart';
import 'package:flutter_encryption/utils/rsa_key_helper.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() {

  group('AES, RSA 테스트', () {
    test('AES 암호화 복호화 테스트', () {
      final String originalText = '안녕하세요';
      final String sessionKey = AesKeyHelper.getRandomString(length: 16);
      final String encryptedText = AesKeyHelper.encryptAES(originalText, sessionKey);
      final String decryptedText = AesKeyHelper.decryptAES(encryptedText, sessionKey);

      print('원본 텍스트: $originalText');
      print('AES 암호화된 텍스트: $encryptedText');
      print('AES 복호화된 텍스트: $decryptedText');
      print('========================================================\n');

      expect(decryptedText, equals(originalText));
    });

    test('RSA 암호화 복호화 테스트', () async {
      final String originalText = '안녕하세요';
      final AsymmetricKeyPair<PublicKey, PrivateKey> keyPair = await RsaKeyHelper.computeRSAKeyPair();
      final String encryptedText = RsaKeyHelper.encryptWithPublicKey(originalText, keyPair.publicKey as RSAPublicKey);
      final String decryptedText = RsaKeyHelper.decryptWithPrivateKey(encryptedText, keyPair.privateKey as RSAPrivateKey);

      print('원본 텍스트: $originalText');
      print('RSA 암호화된 텍스트: $encryptedText');
      print('RSA 복호화된 텍스트: $decryptedText');
      print('========================================================\n');

      expect(decryptedText, equals(originalText));
    });

    test('E2EE', () async {
      // 1. 편지를 보내기 전에, 발신자 Client는 일회용 대칭키(Session Key)를 생성한다.
      final String originalText = '안녕하세요, 반갑습니다. 저는 개발하는 콩입니다.';
      final String sessionKey = AesKeyHelper.getRandomString(length: 16);

      // 2. 발신자 Client는 편지 내용을 Session Key로 암호화한다.
      final String aesEncryptedText = AesKeyHelper.encryptAES(originalText, sessionKey);

      // 3. 발신자 Client는 Server에 수신자의 Public Key를 요청한다.
      final AsymmetricKeyPair<PublicKey, PrivateKey> keyPair = await RsaKeyHelper.computeRSAKeyPair();

      // 4. 발신자 Client는 수신자의 Public Key로 Session Key를 암호화한다.
      // 5. 발신자 Client는 암호화된 편지와 암호화된 Session Key를 Server에 전송한다.
      // 6. Server는 암호화된 편지와 암호화된 Session Key를 저장한다.
      final String encryptedSessionKey = RsaKeyHelper.encryptWithPublicKey(sessionKey, keyPair.publicKey as RSAPublicKey);

      // 7. 수신자 Client는 디바이스에 저장된 수신자의 Private Key로 Session Key를 복호화한다.
      final String decryptedSessionKey = RsaKeyHelper.decryptWithPrivateKey(encryptedSessionKey, keyPair.privateKey as RSAPrivateKey);

      // 8. 수신자 Client는 복호화된 Session Key를 사용해 메시지를 복호화한다.
      final String aesDescryptedText = AesKeyHelper.decryptAES(aesEncryptedText, decryptedSessionKey);

      print('원본 텍스트: $originalText');
      print('AES 암호화된 텍스트: $aesEncryptedText');
      print('AES 복호화된 텍스트: $aesDescryptedText');
      print('========================================================\n');

      expect(originalText, equals(aesDescryptedText));
    });

    test('pem 암호화 복호화 테스트', () async {
      /// Public Key를 전송할 때 Pem 형식으로 변환하여 전송하고, 수신자는 Pem 형식을 다시 PublicKey로 변환하여 사용한다.
      final AsymmetricKeyPair<PublicKey, PrivateKey> keyPair = await RsaKeyHelper.computeRSAKeyPair();
      final PublicKey publicKey = keyPair.publicKey;
      final String publicKeyPem = RsaKeyHelper.encodePublicKeyToPemPKCS1(publicKey as RSAPublicKey);
      final PublicKey decodedPublicKey = RsaKeyHelper.parsePublicKeyFromPem(publicKeyPem);

      expect(publicKey, equals(decodedPublicKey));
    });
  });
}