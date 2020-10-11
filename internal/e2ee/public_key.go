package e2ee

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"crypto/ed25519"

	"github.com/teserakt-io/golang-ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

type ed25519PublicKey = []byte
type ed25519PrivateKey = []byte

type x25519PublicKey = [32]byte
type x25519PrivateKey = [32]byte

func dh(privateKey x25519PrivateKey, publicKey x25519PublicKey) [32]byte {
	var dh [32]byte

	curve25519.ScalarMult(&dh, &privateKey, &publicKey)

	return dh
}

type x25519KeyPair struct {
	publicKey  x25519PublicKey
	privateKey x25519PrivateKey
}

func generateX25519KeyPair() (*x25519KeyPair, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var copyPrivateKey x25519PrivateKey
	copy(copyPrivateKey[:], privateKey)

	var copyPublicKey x25519PublicKey
	copy(copyPublicKey[:], publicKey)

	return &x25519KeyPair{
		publicKey:  copyPublicKey,
		privateKey: copyPrivateKey,
	}, nil
}

type ed25519KeyPair struct {
	publicKey  []byte
	privateKey []byte
}

func generateEd25519KeyPair() (*ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ed25519KeyPair{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (e *ed25519KeyPair) publicEd25519KeyToCurve25519() (x25519PublicKey, error) {
	return publicEd25519KeyToCurve25519(e.publicKey)
}

func (e *ed25519KeyPair) privateEd25519KeyToCurve25519() x25519PrivateKey {
	return privateEd25519KeyToCurve25519(e.privateKey)
}

func publicEd25519KeyToCurve25519(edPubKey ed25519PublicKey) (x25519PublicKey, error) {
	var edPk [ed25519.PublicKeySize]byte
	var curveKey [32]byte
	copy(edPk[:], edPubKey)
	if !extra25519.PublicKeyToCurve25519(&curveKey, &edPk) {
		return curveKey, errors.New("Ed25519ToCurve25519PublicKeyConvertError")
	}

	return curveKey, nil
}

func privateEd25519KeyToCurve25519(edSKey ed25519PrivateKey) x25519PrivateKey {
	var edSk [ed25519.PrivateKeySize]byte
	var curveKey [32]byte
	copy(edSk[:], edSKey)
	extra25519.PrivateKeyToCurve25519(&curveKey, &edSk)

	return curveKey
}

// https://github.com/golang/crypto/blob/5c72a883971a/ssh/keys.go#L1456
func fingerprint(pubKey []byte) string {
	sha256sum := sha256.Sum256(pubKey)
	hexarray := make([]string, len(sha256sum))
	for i, c := range sha256sum {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(hexarray, ":")
}
