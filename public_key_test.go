package e2ee

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"golang.org/x/crypto/curve25519"
)

func TestEd25519ToX25519(t *testing.T) {
	ed25519KeyPair1, err := generateEd25519KeyPair()
	assert.Nil(t, err)

	ed25519KeyPair2, err := generateEd25519KeyPair()
	assert.Nil(t, err)

	x25519PrivateKey1 := ed25519KeyPair1.privateEd25519KeyToCurve25519()
	x25519PublicKey1, err := ed25519KeyPair1.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)

	x25519PrivateKey2 := ed25519KeyPair2.privateEd25519KeyToCurve25519()
	x25519PublicKey2, err := ed25519KeyPair2.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)

	var pmk1 [32]byte
	var pmk2 [32]byte

	curve25519.ScalarMult(&pmk1, &x25519PrivateKey2, &x25519PublicKey1)
	curve25519.ScalarMult(&pmk2, &x25519PrivateKey1, &x25519PublicKey2)

	assert.Equal(t, pmk1, pmk2)
}

func TestDH(t *testing.T) {
	sRatchetPrivateKey := make([]byte, curve25519.ScalarSize)
	_, err := io.ReadFull(rand.Reader, sRatchetPrivateKey)
	assert.Nil(t, err)

	// これは相手に送りつける
	// 毎回変える
	sRatchetPubKey, err := curve25519.X25519(sRatchetPrivateKey, curve25519.Basepoint)
	assert.Nil(t, err)

	rSignedPrePrivateKey := make([]byte, curve25519.ScalarSize)
	_, err = io.ReadFull(rand.Reader, rSignedPrePrivateKey)
	assert.Nil(t, err)

	// これは相手に送りつける
	// 毎回変える
	rSignedPrePubKey, err := curve25519.X25519(rSignedPrePrivateKey, curve25519.Basepoint)
	assert.Nil(t, err)

	sA, rA := a(sRatchetPrivateKey, sRatchetPubKey, rSignedPrePrivateKey, rSignedPrePubKey)
	assert.Equal(t, sA, rA)
}

func a(srsk []byte, srpk []byte, rspsk []byte, rsppk []byte) ([32]byte, [32]byte) {
	var sRatchetPrivateKey [32]byte
	copy(sRatchetPrivateKey[:], srsk)

	var sRatchetPubKey [32]byte
	copy(sRatchetPubKey[:], srpk)

	var rSignedPrePrivateKey [32]byte
	copy(rSignedPrePrivateKey[:], rspsk)

	var rSignedPrePubKey [32]byte
	copy(rSignedPrePubKey[:], rsppk)

	var sA [32]byte
	curve25519.ScalarMult(&sA, &sRatchetPrivateKey, &rSignedPrePubKey)

	var rA [32]byte
	curve25519.ScalarMult(&rA, &rSignedPrePrivateKey, &sRatchetPubKey)

	return sA, rA
}
