package e2ee

import (
	"crypto/ed25519"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// identityKey 1 度限り
// ephemeralKey 定期更新
// signedPreKey 定期交換
// oneTimePreKey x N

// TODO(v): oneTimePreKey に対応する
type preKeyBundle struct {
	identityKey     []byte
	signedPreKey    x25519PublicKey
	preKeySignature []byte
}

func rootKey(dh1 [32]byte, dh2 [32]byte, dh3 [32]byte) ([]byte, error) {
	hash := sha256.New
	secret := secret(dh1, dh2, dh3)

	// 0 でうまったものを生成
	salt := make([]byte, hash().Size())
	info := []byte("SoraText")
	hkdf := hkdf.New(hash, secret, salt, info)

	rootKey := make([]byte, hash().Size())

	if _, err := io.ReadFull(hkdf, rootKey); err != nil {
		return nil, err
	}

	return rootKey, nil
}

// remote 関連は remotePreKeyBundle struct で管理したい
func senderRootKey(selfX25519IdentityPrivateKey x25519PrivateKey, selfEphemeralPrivateKey x25519PrivateKey,
	remoteX25519IdentityKey x25519PublicKey, remoteSignedPreKey x25519PublicKey) ([]byte, error) {
	// TODO(v): OneTimePreKey dh4 にも対応する
	dh1 := dh(selfX25519IdentityPrivateKey, remoteSignedPreKey)
	dh2 := dh(selfEphemeralPrivateKey, remoteX25519IdentityKey)
	dh3 := dh(selfEphemeralPrivateKey, remoteSignedPreKey)

	return rootKey(dh1, dh2, dh3)
}

func receiverRootKey(selfIdentityPrivateKey x25519PrivateKey, selfPrePrivateKey x25519PrivateKey,
	remoteX25519IdentityKey x25519PublicKey, remoteEphemeralKey x25519PublicKey) ([]byte, error) {
	// TODO(v): OneTimePreKey dh4 にも対応する
	dh1 := dh(selfPrePrivateKey, remoteX25519IdentityKey)
	dh2 := dh(selfIdentityPrivateKey, remoteEphemeralKey)
	dh3 := dh(selfPrePrivateKey, remoteEphemeralKey)

	return rootKey(dh1, dh2, dh3)
}

func secret(dh1 [32]byte, dh2 [32]byte, dh3 [32]byte) []byte {
	secret := make([]byte, 0, 96)
	secret = append(secret, dh1[:]...)
	secret = append(secret, dh2[:]...)
	secret = append(secret, dh3[:]...)
	return secret
}

type ephemeralKeyPair struct {
	privateKey x25519PrivateKey
	publicKey  x25519PublicKey
}

func generateIdentityKeyPair() (*ed25519KeyPair, error) {
	return generateEd25519KeyPair()
}

func generatePreKeyPair() (*x25519KeyPair, error) {
	return generateX25519KeyPair()
}

// これは相手に送りつける
// 毎回変える
func generateEphemeralKeyPair() (*x25519KeyPair, error) {
	return generateX25519KeyPair()
}

func generatePreKeyBundle(identityKeyPair ed25519KeyPair, preKeyPair x25519KeyPair) *preKeyBundle {
	signature := ed25519.Sign(identityKeyPair.privateKey, preKeyPair.publicKey[:])
	return &preKeyBundle{
		identityKey:     identityKeyPair.publicKey,
		signedPreKey:    preKeyPair.publicKey,
		preKeySignature: signature,
	}
}
