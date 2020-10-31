package e2ee

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestX3DH(t *testing.T) {
	aliceIdentityKeyPair, err := generateEd25519KeyPair()
	assert.Nil(t, err)
	aliceX25519EphemeralKeyPair, err := generateEphemeralKeyPair()

	bobIdentityKeyPair, err := generateEd25519KeyPair()
	assert.Nil(t, err)

	bobPreKeyPair, err := generatePreKeyPair()
	assert.Nil(t, err)

	aliceX25519IdentityPrivateKey := aliceIdentityKeyPair.privateEd25519KeyToCurve25519()
	aliceX25519IdentityPublicKey, err := aliceIdentityKeyPair.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)

	bobX25519IdentityPublicKey, err := bobIdentityKeyPair.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)
	bobX25519IdentityPrivateKey := bobIdentityKeyPair.privateEd25519KeyToCurve25519()

	aliceRootKey, err := senderRootKey(aliceX25519IdentityPrivateKey, aliceX25519EphemeralKeyPair.privateKey, bobX25519IdentityPublicKey, bobPreKeyPair.publicKey)
	assert.Nil(t, err)
	bobRootKey, err := receiverRootKey(bobX25519IdentityPrivateKey, bobPreKeyPair.privateKey, aliceX25519IdentityPublicKey, aliceX25519EphemeralKeyPair.publicKey)
	assert.Nil(t, err)

	assert.Equal(t, aliceRootKey, bobRootKey)
}
