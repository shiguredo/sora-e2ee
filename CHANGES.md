# 変更履歴

- CHANGE
    - 下位互換のない変更
- UPDATE
    - 下位互換がある変更
- ADD
    - 下位互換がある追加
- FIX
    - バグ修正

## develop

- [CHANGE] e2ee インスタンスを作成できるようにする
- [UPDATE] go 1.17 に対応する
- [UDPATE] wasm_exec.js を go 1.17 のものを利用する
- [ADD] wasm.wasm のテストを追加する

## 2020.2

- [CHANGE] e2ee を利用し始める時は e2ee.init() を必ず呼ぶように変更する
    - これで再読み込みなども不要にできるようになる
- [UDPATE] バージョンを Makefile に定義するようにする
- [ADD] e2ee.version() を追加
    - "2020.2" などの文字列を返す
- [ADD] バイナリを dist 以下に置くようにする

## 2020.1

**祝リリース**
