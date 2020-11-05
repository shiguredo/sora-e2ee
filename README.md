# Sora E2EE Go ライブラリ

[![GitHub tag](https://img.shields.io/github/tag/shiguredo/sora-e2ee.svg)](https://github.com/shiguredo/sora-e2ee)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## 時雨堂のオープンソースソフトウェアについて

利用前に https://github.com/shiguredo/oss をお読みください。

## 概要

WebRTC SFU Sora 利用時に E2EE をブラウザで実現するためのライブラリです。
これ単体では利用できず [Sora JS SDK](https://github.com/shiguredo/sora-js-sdk) から呼び出して利用します。

## ドキュメント

**詳細な仕様についてはドキュメントをご確認ください**

https://sora-e2ee.shiguredo.jp/

## FAQ

- このライブラリのライセンスはなんですか？
    - Apache License 2.0 です
- E2EE を利用するメリットはなんですか？
    - WebRTC SFU 側で音声や映像の解析が困難になります
- E2EE の鍵合意プロトコルはなにを使用していますか？
    - Signal プロトコルの X3DH を利用しています
- E2EE のメッセージ暗号アルゴリズムはなにを使用していますか？
    - Signal プロトコルの Double Ratchet アルゴリズムを利用しています
- E2EE 用のキーペアはどうやって生成すればいいですか？
    - キーペアは WebAssembly で動的に生成されます
- E2EE に利用する暗号方式は何を採用していますか？
    - AES-GCM 128 を採用しています
- E2EE に利用する暗号鍵を生成する鍵導出関数はなんですか？
    - HKDF を利用します
- E2EE に利用する IV の生成方法はなんですか？
    - HKDF を利用して生成された 96 ビットの値と前半 64 ビットを 0 パディングした 32 ビットのカウンターの XOR を利用します
- E2EE 用のキーペアはどう扱われますか？
    - 利用するキーペアは WebAssembly 側で動的に生成されます
- E2EE 用の鍵は Sora に送られますか？
    - 送られません Sora には `{e2ee: true}` という値のみが Sora に送られます
    - この値は E2EE を利用しているかどうかを認証サーバ側で把握するために利用されます
- E2EE 用の wasm バイナリはどう用意すればいいですか？
    - 自前でビルドしてください Go が必要になります
    - その後 Sora JavaScript SDK で `{e2ee_wasm_url: "https://example.com/wasm.wasm"}` のように設定してください
- E2EE で利用するキーの利用回数が 2^32-1 回を超えたらどうなりますか？
    - 切断します
- E2EE はどうやって実現していますか？
    - Insertable Streams API を利用しています
- E2EE を利用すると遅くなりますか？
    - 暗号化/復号が入るので遅くはなりますが Web Worker を利用することで可能な範囲で高速化はしています
- E2EE を利用すると CPU 使用率は上がりますか？
    - E2EE 用の暗号化/復号を行うため CPU 使用率は上がります
- 暗号ライブラリは何を利用していますか？
    - WebCrypto を利用しています
- 定期的な鍵交換は行いますか？
    - チャネルへの参加、離脱が発生するたびにマテリアルキーが更新されます
- [Secure Frame](https://tools.ietf.org/html/draft-omara-sframe-00) は利用していますか？
    - 採用しています
    - 暗号化には AES-GCM 128 を採用しています

## 利用可能環境

- Chrome M87 以降
- Edge 87 以降

## 利用技術

- [WebRTC Insertable Media using Streams](https://w3c.github.io/webrtc-insertable-streams/)
    - [WebRTC Insertable Streams \- Chrome Platform Status](https://www.chromestatus.com/feature/6321945865879552)
- [Web Cryptography API](https://w3c.github.io/webcrypto/)
- [Web workers](https://html.spec.whatwg.org/multipage/workers.html#workers)
- [Streams](https://streams.spec.whatwg.org/)
    - [Streams API: transferable streams \- Chrome Platform Status](https://www.chromestatus.com/feature/5298733486964736)
- WebAssembly
    - [WebAssembly](https://webassembly.org/)
- The X3DH Key Agreement Protocol
    - [Signal >> Specifications >> The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- The Double Ratchet Algorithm
    - [Signal >> Specifications >> The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- Go "syscall/js"
    - [js \- The Go Programming Language](https://golang.org/pkg/syscall/js/)
- Secure Frame
    - [Secure Frame \(SFrame\)](https://tools.ietf.org/html/draft-omara-sframe-00)

## Sora JavaScript SDK からの利用方法

```javascript
let sora = Sora.connection('wss://example.com/signaling');
let channelId = 'sora-e2ee';
let sendrecv = sora.sendrecv(channelId, null, {e2ee: true, e2ee_wasm_url: "https://example.com/e2ee/wasm.wasm"});

navigator.mediaDevices.getUserMedia({audio: true, video: true})
  .then(mediaStream => {
    // connect
    sendrecv.connect(mediaStream)
      .then(stream => {
        // stream を video.src に追加する等の処理
      });
  })
  .catch(e => {
    console.error(e);
  });

// disconnect
sendrecv.disconnect()
  .then(() => {
    // video を止める等の処理
  });

// event
sendrecv.on('disconnect', function(e) {
  console.error(e);
});
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
