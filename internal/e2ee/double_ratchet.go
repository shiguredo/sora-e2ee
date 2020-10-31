package e2ee

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

type ratchetHeader struct {
	DH  [32]byte
	PN  uint32
	N   uint32
	raw []byte
}

type ratchetKeyPair struct {
	privateKey x25519PrivateKey
	publicKey  x25519PublicKey
}

/// skipped 向け
type messageKey struct {
	key   []byte
	nonce []byte
}

type mkskippedKey struct {
	DH [32]byte
	N  uint32
}

type ratchetState struct {
	selfDH         ratchetKeyPair
	remoteDH       [32]byte
	rootKey        []byte
	selfChainKey   []byte
	remoteChainKey []byte
	selfN          uint32
	remoteN        uint32
	PN             uint32
	mkskipped      map[mkskippedKey]messageKey
}

func generateRatchetKeyPair() (*ratchetKeyPair, error) {
	x25519KeyPair, err := generateX25519KeyPair()
	if err != nil {
		return nil, err
	}

	return &ratchetKeyPair{
		privateKey: x25519KeyPair.privateKey,
		publicKey:  x25519KeyPair.publicKey,
	}, nil
}

func kdfRk(previousRootKey []byte, senderRatchetKeyPrivate x25519PrivateKey, receiverRatchetKeyPublic x25519PublicKey) ([]byte, []byte, error) {
	a := dh(senderRatchetKeyPrivate, receiverRatchetKeyPublic)

	hash := sha256.New
	info := []byte("SoraRatchet")
	hkdf := hkdf.New(hash, a[:], previousRootKey, info)

	rootKey := make([]byte, 32)
	chainKey := make([]byte, 32)

	if _, err := io.ReadFull(hkdf, rootKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(hkdf, chainKey); err != nil {
		return nil, nil, err
	}

	return rootKey, chainKey, nil
}

func senderRatchetInit(sk []byte, preKeyBundle preKeyBundle) (*ratchetState, error) {
	ratchetKeyPair, err := generateRatchetKeyPair()
	if err != nil {
		return nil, err
	}

	rootKey, chainKey, err := kdfRk(sk, ratchetKeyPair.privateKey, preKeyBundle.signedPreKey)
	if err != nil {
		return nil, err
	}
	return &ratchetState{
		selfDH:       *ratchetKeyPair,
		remoteDH:     preKeyBundle.signedPreKey,
		rootKey:      rootKey,
		selfChainKey: chainKey,
		selfN:        0,
		remoteN:      0,
		PN:           0,
		mkskipped:    make(map[mkskippedKey]messageKey),
	}, nil
}

func receiverRatchetInit(sk []byte, signedPreKeyPublic x25519PublicKey, signedPreKeyPrivate x25519PrivateKey) *ratchetState {
	return &ratchetState{
		// 初回は receiver の signedPreKey を利用する
		// A = ECDH-X25519(Sender_RatchetKey, Receiver_SignedPreKey)
		selfDH: ratchetKeyPair{
			publicKey:  signedPreKeyPublic,
			privateKey: signedPreKeyPrivate,
		},
		rootKey:   sk,
		selfN:     0,
		remoteN:   0,
		PN:        0,
		mkskipped: make(map[mkskippedKey]messageKey),
	}
}

func parseHeader(header []byte) (*ratchetHeader, error) {
	ratchetHeader := &ratchetHeader{raw: header}
	buf := bytes.NewReader(header)
	if err := binary.Read(buf, binary.BigEndian, &ratchetHeader.DH); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &ratchetHeader.PN); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &ratchetHeader.N); err != nil {
		return nil, err
	}

	return ratchetHeader, nil
}

// 送られてきた header.dh を引数にとる
func (rs *ratchetState) ratchet(remoteDH [32]byte) error {
	rs.PN = rs.selfN
	rs.selfN = 0
	rs.remoteN = 0
	rs.remoteDH = remoteDH

	rootKey, remoteChainKey, err := kdfRk(rs.rootKey, rs.selfDH.privateKey, rs.remoteDH)
	if err != nil {
		return err
	}
	rs.rootKey = rootKey
	rs.remoteChainKey = remoteChainKey

	ratchetKeyPair, err := generateRatchetKeyPair()
	if err != nil {
		return err
	}
	rs.selfDH = *ratchetKeyPair

	rootKey, selfChainKey, err := kdfRk(rs.rootKey, rs.selfDH.privateKey, rs.remoteDH)
	if err != nil {
		return err
	}

	rs.rootKey = rootKey
	rs.selfChainKey = selfChainKey

	return nil
}

func (rs *ratchetState) ratchetDecrypt(header []byte, ciphertext []byte, ad []byte) ([]byte, error) {
	ratchetHeader, err := parseHeader(header)
	if err != nil {
		return nil, err
	}

	plaintext, err := rs.trySkippedMessageKeys(ratchetHeader, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	if plaintext != nil {
		return plaintext, nil
	}

	remoteDH := ratchetHeader.DH

	if rs.remoteDH != remoteDH {
		if err := rs.skipMessageKeys(ratchetHeader.PN); err != nil {
			return nil, err
		}
		if err := rs.ratchet(remoteDH); err != nil {
			return nil, err
		}
	}

	if err := rs.skipMessageKeys(ratchetHeader.N); err != nil {
		return nil, err
	}

	messageKey, nonce, err := rs.newReceiverMessageKey()
	if err != nil {
		return nil, err
	}
	rs.newReceiverChainKey()
	rs.remoteN++

	plaintext, err = decrypt(messageKey, nonce, ciphertext, append(ad, header...))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// チェインキーは生成済みとする
func (rs *ratchetState) ratchetEncrypt(plaintext []byte, ad []byte) ([]byte, []byte, error) {
	messageKey, nonce, err := rs.newSenderMessageKey()
	if err != nil {
		return nil, nil, err
	}

	// chainkey の更新
	rs.newSenderChainKey()

	header, err := rs.header()
	if err != nil {
		return nil, nil, err
	}

	rs.selfN++

	ciphertext, err := encrypt(messageKey, nonce, plaintext, append(ad, header...))
	if err != nil {
		return nil, nil, err
	}

	return header, ciphertext, nil
}

func (rs *ratchetState) header() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, rs.selfDH.publicKey); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, rs.PN); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, rs.selfN); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func newChainKey(chainKey []byte) []byte {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte{2})
	return mac.Sum(nil)
}

func (rs *ratchetState) newReceiverChainKey() {
	rs.remoteChainKey = newChainKey(rs.remoteChainKey)
}

func (rs *ratchetState) newSenderChainKey() {
	rs.selfChainKey = newChainKey(rs.selfChainKey)
}

// KDF_CK
func newMessageKey(chainKey []byte) ([]byte, []byte, error) {
	h := hmac.New(sha256.New, chainKey)
	h.Write([]byte{1})
	seed := h.Sum(nil)

	hash := sha256.New
	salt := make([]byte, 44)
	info := []byte("SoraMessageKeys")
	hkdf := hkdf.New(hash, seed, salt, info)

	// AES-GCM は 32 でよし
	messageKey := make([]byte, 32)
	// 12 ほしい
	nonce := make([]byte, 12)

	if _, err := io.ReadFull(hkdf, messageKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(hkdf, nonce); err != nil {
		return nil, nil, err
	}

	return messageKey, nonce, nil
}

func (rs *ratchetState) newSenderMessageKey() ([]byte, []byte, error) {
	return newMessageKey(rs.selfChainKey)
}

func (rs *ratchetState) newReceiverMessageKey() ([]byte, []byte, error) {
	return newMessageKey(rs.remoteChainKey)
}

func (rs *ratchetState) trySkippedMessageKeys(header *ratchetHeader, ciphertext []byte, AD []byte) ([]byte, error) {
	mkskippedKey := &mkskippedKey{
		DH: header.DH,
		N:  header.N,
	}
	messageKey, ok := rs.mkskipped[*mkskippedKey]
	if ok {
		delete(rs.mkskipped, *mkskippedKey)
		plaintext, err := decrypt(messageKey.key, messageKey.nonce, ciphertext, append(AD, header.raw...))
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	}
	return nil, nil
}

// MAX_SKIP定数も定義する必要がある。
// これは、1つのチェーンでスキップできるメッセージキーの最大数を指定します。
// ルーチンでのメッセージの紛失や遅延を許容するのに十分な高さに設定しなければならないが、
// 悪意のある送信者が過剰な受信者の計算を引き起こすことができないように十分に低い値に設定しなければならない。
var maxSkip uint32 = 10

func (rs *ratchetState) skipMessageKeys(until uint32) error {
	if rs.remoteN+maxSkip < until {
		// TODO(v): 切断を促すエラー処理
		return errors.New("NotImplementedError")
	}

	if rs.remoteChainKey != nil {
		for rs.remoteN < until {
			var mkskippedKey = &mkskippedKey{
				DH: rs.remoteDH,
				N:  rs.remoteN,
			}
			key, nonce, err := rs.newReceiverMessageKey()
			if err != nil {
				return err
			}

			rs.newReceiverChainKey()
			var messageKey = &messageKey{
				key:   key,
				nonce: nonce,
			}

			rs.mkskipped[*mkskippedKey] = *messageKey
			rs.remoteN++
		}
	}

	return nil
}
