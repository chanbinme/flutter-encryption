# Flutter E2EE (End-to-End Encryption) 구현

## 소개
이 프로젝트는 Flutter를 사용하여 End-to-End Encryption (E2EE)을 구현한 예제입니다. E2EE는 통신의 양 끝점 사이에서 메시지를 안전하게 암호화하여, 오직 발신자와 수신자만이 메시지 내용을 읽을 수 있도록 보장하는 보안 기술입니다.
Flutter를 통해 E2EE에 필요한 암호화 로직을 구현해봤습니다.

</br>

## E2EE의 중요성
- 프라이버시 보호: 메시지는 전송 과정에서 암호화되어, 중간자(서버 포함)가 내용을 볼 수 없습니다.
- 데이터 무결성: 메시지가 변조되지 않았음을 보장합니다.
- 신뢰성 향상: 사용자들은 자신의 통신이 안전하다는 확신을 갖게 됩니다.

</br>

## 적용 순서
### 계정 생성
1. Client는 Server에 회원이 첫 로그인지 확인을 요청한다.
2. 첫 로그인이라면 Client는 비대칭키(Public Key, Private Key)를 생성한다.
3. Client는 Private Key를 고객 디바이스에 저장한다.
4. Client는 Public Key를 Pem 파일 형식으로 변환한다.
5. Client는 Public Key Pem를 Server에 전달한다.
6. Server는 Public Key Pem을 저장한다.

### 데이터 보내기
1. 데이터를 보내기 전에, 발신자 Client는 일회용 대칭키(Session Key)를 생성한다.
2. 발신자 Client는 데이터를 Session Key로 암호화한다.
3. 발신자 Client는 Server에 수신자의 Public Key를 요청한다.
4. 발신자 Client는 수신자의 Public Key로 Session Key를 암호화한다.
5. 발신자 Client는 암호화된 데이터와 암호화된 Session Key를 Server에 전송한다.
6. Server는 암호화된 데이터와 암호화된 Session Key를 저장한다.
7. 수신자 Client는 디바이스에 저장된 수신자의 Private Key로 Session Key를 복호화한다.
8. 수신자 Client는 복호화된 Session Key를 사용해 메시지를 복호화한다.

</br>

### 사용되는 암호 알고리즘
이 프로젝트에서는 두 가지 암호화 알고리즘을 사용합니다.
- RSA: 공개키 암호화 방식으로, 키 교환에 사용됩니다.
- AES: 대칭키 암호화 방식으로, 실제 메시지 암호화에 사용됩니다.
