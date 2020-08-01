# Sora E2EE WebAssembly ライブラリ

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## 概要

WebRTC SFU Sora 利用時に E2EE をブラウザで実現するためのライブラリです。
これ単体では利用できず Sora JS SDK と Sora E2EE ライブラリの２つと組み合わせて使います。

## 利用技術

- WebAssembly
    - [WebAssembly \| MDN](https://developer.mozilla.org/ja/docs/WebAssembly)
- The XEdDSA and VXEdDSA Signature Schemes
    - [Signal >> Specifications >> The XEdDSA and VXEdDSA Signature Schemes](https://signal.org/docs/specifications/xeddsa/)
- The X3DH Key Agreement Protocol
    - [Signal >> Specifications >> The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- The Double Ratchet Algorithm
    - [Signal >> Specifications >> The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- Go "syscall/js"
    - [js \- The Go Programming Language](https://golang.org/pkg/syscall/js/)

## メッセージプロトコル

- WebRTC SFU Sora 経由で送られます
- Connection ID は Clockwork Base32 の文字列をそのまま利用しています

### メッセージヘッダー

```erlang
-define(E2EE_PRE_KEY_MESSAGE_TYPE, 0).
-define(E2EE_CIPHER_MESSAGE_TYPE,  1).

<<MessageType:8, Reserved:8, CiphertextLength:16>>
```

- MessageType
    - 8 ビット
    - 0
        - PreKey メッセージ
    - 1
        - Cipher メッセージ
- Reserved
    - 8 ビット
    - 必ず 0
- CiphertextLength
    - 16 ビット
    - 暗号化されたメッセージのバイト数です

### PreKey メッセージ

```erlang
<<?E2EE_PRE_KEY_MESSAGE_TYPE:8, 0:8, 0:16,
  SrcConnectionID:26/binary, DstConnectionID:26/binary,
  IdentityKey:32/binary, EphemeralKey:32/binary>>
```

### Cipher メッセージ

```erlang
<<?E2EE_CIPHER_MESSAGE_TYPE:8, 0:8, CiphertextLength:16,
  SrcConnectionID:26/binary, DstConnectionID:26/binary,
  %% ここは CipherMessage ヘッダー
  RachetPublicKey:32/binary, N:32, NP:32,
  %% 本体
  Ciphertext/binary>>
```

## 利用方法

```javascript
// 初期化
e2ee.init();

// connection.created 通知が飛んできたときの処理
e2ee.start(remoteConnectionId, remoteIdentityKey, remoteSignedPreKey, remotePreKeySignature);

e2ee.receive_message(message);

e2ee.stop(remoteConnectionId);
```

```javascript
// PreKey バンドルを登録する
e2ee.addPreKeyBundle(remoteIdentityKey, remoteSignedPreKey, remotePreKeySignature)
```

## ライセンス

```
Copyright 2020, Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
