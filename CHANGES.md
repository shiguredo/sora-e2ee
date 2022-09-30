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

## 2020.2.1

- [UPDATE] Go 1.19 に上げる
- [UPDATE] github.com/stretchr/testify を v1.8.0 に上げる
- [UPDATE] github.com/teserakt-io/golang-ed25519 を v0.0.0-20210104091850-3888c087a4c8 に上げる
- [UPDATE] golang.org/x/crypto を v0.0.0-20220926161630-eccd6366d1be に上げる

## 2020.2

- [CHANGE] e2ee を利用し始める時は e2ee.init() を必ず呼ぶように変更する
    - これで再読み込みなども不要にできるようになる
- [UDPATE] バージョンを Makefile に定義するようにする
- [ADD] e2ee.version() を追加
    - "2020.2" などの文字列を返す
- [ADD] バイナリを dist 以下に置くようにする

## 2020.1

**祝リリース**
