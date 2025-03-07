import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as encrypt;

class AesKeyHelper {
  // AES 암호화
  static String encryptAES(String text, String sessionKey) {
    final encrypt.IV iv = encrypt.IV.fromUtf8(sessionKey);
    final encrypt.Encrypter encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key.fromUtf8(sessionKey), mode: encrypt.AESMode.ctr, padding: null));
    return encrypter.encrypt(text, iv: iv).base64;
  }

  // AES 복호화
  static String decryptAES(String encrypted, String sessionKey) {
    final encrypt.IV iv = encrypt.IV.fromUtf8(sessionKey);
    final encrypt.Encrypter encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key.fromUtf8(sessionKey), mode: encrypt.AESMode.ctr, padding: null));
    final Uint8List encryptedBytesWithSalt = base64.decode(encrypted);
    final Uint8List encryptedBytes = encryptedBytesWithSalt.sublist(0, encryptedBytesWithSalt.length,);
    final String decrypted = encrypter.decrypt64(base64.encode(encryptedBytes), iv: iv);
    return decrypted;
  }

  // 랜덤 문자열 생성
  static String getRandomString({required int length}) {
    final String chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
    final Random rnd = Random();
    String result = '';
    for (int i = 0; i < length; i++) {
      result += chars[rnd.nextInt(chars.length)];
    }
    return result;
  }
}