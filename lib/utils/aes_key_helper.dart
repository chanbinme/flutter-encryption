import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as encrypt;

class AesKeyHelper {
  static final String aesEncryptionKey = _getRandomString(length: 16);
  static final encrypt.IV iv = encrypt.IV.fromUtf8(aesEncryptionKey);
  static final encrypt.Encrypter encrypter = encrypt.Encrypter(encrypt.AES(encrypt.Key.fromUtf8(aesEncryptionKey), mode: encrypt.AESMode.ctr, padding: null));

  // AES 암호화
  static String encryptAES(String text) => encrypter.encrypt(text, iv: iv).base64;

  // AES 복호화
  static String decryptAES(String encrypted) {
    final Uint8List encryptedBytesWithSalt = base64.decode(encrypted);
    final Uint8List encryptedBytes = encryptedBytesWithSalt.sublist(0, encryptedBytesWithSalt.length,);
    final String decrypted = encrypter.decrypt64(base64.encode(encryptedBytes), iv: iv);
    return decrypted;
  }

  // 랜덤 문자열 생성
  static String _getRandomString({required int length}) {
    final String chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
    final Random rnd = Random();
    String result = '';
    for (int i = 0; i < length; i++) {
      result += chars[rnd.nextInt(chars.length)];
    }
    return result;
  }
}