package e2ee

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDoubleRatchet(t *testing.T) {
	alice, err := generateIdentityKeyPair()
	assert.Nil(t, err)

	aliceX25519EphemeralKeyPair, err := generateEphemeralKeyPair()
	assert.Nil(t, err)

	bob, err := generateIdentityKeyPair()
	assert.Nil(t, err)

	bobPreKeyPair, err := generatePreKeyPair()
	assert.Nil(t, err)

	bobPreKeyBundle := generatePreKeyBundle(*bob, *bobPreKeyPair)

	aliceX25519IdentityPrivateKey := alice.privateEd25519KeyToCurve25519()
	aliceX25519IdentityPublicKey, err := alice.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)

	bobX25519IdentityPrivateKey := bob.privateEd25519KeyToCurve25519()
	bobX25519IdentityPublicKey, err := bob.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)

	aliceRootKey, err := senderRootKey(aliceX25519IdentityPrivateKey, aliceX25519EphemeralKeyPair.privateKey, bobX25519IdentityPublicKey, bobPreKeyPair.publicKey)
	assert.Nil(t, err)

	bobRootKey, err := receiverRootKey(bobX25519IdentityPrivateKey, bobPreKeyPair.privateKey, aliceX25519IdentityPublicKey, aliceX25519EphemeralKeyPair.publicKey)
	assert.Nil(t, err)

	assert.Equal(t, aliceRootKey, bobRootKey)

	plaintext := []byte("hello world")
	// 関数化
	var ad []byte = append(alice.publicKey[:], bob.publicKey[:]...)

	aliceRatchetState, err := senderRatchetInit(aliceRootKey, *bobPreKeyBundle)
	bobRatchetState := receiverRatchetInit(bobRootKey, bobPreKeyBundle.signedPreKey, bobPreKeyPair.privateKey)

	// Alice 1 回目のメッセージ
	header, ciphertext, err := aliceRatchetState.ratchetEncrypt(plaintext, ad)
	assert.Nil(t, err)

	plaintext1, err := bobRatchetState.ratchetDecrypt(header, ciphertext, ad)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, plaintext1)

	// Alice 2 回目のメッセージ
	header2, ciphertext2, err := aliceRatchetState.ratchetEncrypt(plaintext, ad)
	assert.Nil(t, err)

	plaintext2, _ := bobRatchetState.ratchetDecrypt(header2, ciphertext2, ad)

	assert.Equal(t, plaintext, plaintext2)

	// Alice 3 回目のメッセージ
	header3, ciphertext3, err := aliceRatchetState.ratchetEncrypt(plaintext, ad)
	assert.Nil(t, err)
	plaintext3, err := bobRatchetState.ratchetDecrypt(header3, ciphertext3, ad)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, plaintext3)

	// Bob 1 回目のメッセージ
	header4, ciphertext4, err := bobRatchetState.ratchetEncrypt(plaintext, ad)
	assert.Nil(t, err)
	plaintext4, err := aliceRatchetState.ratchetDecrypt(header4, ciphertext4, ad)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, plaintext4)

	// Alice 4 回目のメッセージ
	header5, ciphertext5, err := aliceRatchetState.ratchetEncrypt(plaintext, ad)
	assert.Nil(t, err)
	plaintext5, err := bobRatchetState.ratchetDecrypt(header5, ciphertext5, ad)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, plaintext5)
}

func TestSkipMessageKey(t *testing.T) {
	alice, err := generateIdentityKeyPair()
	assert.Nil(t, err)
	aliceX25519EphemeralKeyPair, err := generateEphemeralKeyPair()
	assert.Nil(t, err)

	bob, err := generateIdentityKeyPair()
	assert.Nil(t, err)
	bobPreKeyPair, err := generatePreKeyPair()
	assert.Nil(t, err)

	bobPreKeyBundle := generatePreKeyBundle(*bob, *bobPreKeyPair)

	aliceX25519IdentityPrivateKey := alice.privateEd25519KeyToCurve25519()
	aliceX25519IdentityPublicKey, err := alice.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)

	bobX25519IdentityPrivateKey := bob.privateEd25519KeyToCurve25519()
	bobX25519IdentityPublicKey, err := bob.publicEd25519KeyToCurve25519()
	assert.Nil(t, err)

	aliceRootKey, err := senderRootKey(aliceX25519IdentityPrivateKey, aliceX25519EphemeralKeyPair.privateKey, bobX25519IdentityPublicKey, bobPreKeyPair.publicKey)
	assert.Nil(t, err)
	bobRootKey, err := receiverRootKey(bobX25519IdentityPrivateKey, bobPreKeyPair.privateKey, aliceX25519IdentityPublicKey, aliceX25519EphemeralKeyPair.publicKey)
	assert.Nil(t, err)

	assert.Equal(t, aliceRootKey, bobRootKey)

	plaintext := []byte("hello world")
	// 関数化
	var ad []byte = append(alice.publicKey[:], bobPreKeyBundle.identityKey[:]...)

	aliceRatchetState, err := senderRatchetInit(aliceRootKey, *bobPreKeyBundle)
	assert.Nil(t, err)
	bobRatchetState := receiverRatchetInit(bobRootKey, bobPreKeyBundle.signedPreKey, bobPreKeyPair.privateKey)

	// Alice 1 回目のメッセージ
	header, ciphertext, err := aliceRatchetState.ratchetEncrypt(plaintext, ad)
	assert.Nil(t, err)

	plaintext1, err := bobRatchetState.ratchetDecrypt(header, ciphertext, ad)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, plaintext1)

	// Alice 2 回目のメッセージ
	header2, ciphertext2, err := aliceRatchetState.ratchetEncrypt(plaintext, ad)

	// Alice 3 回目のメッセージ
	header3, ciphertext3, err := aliceRatchetState.ratchetEncrypt(plaintext, ad)
	assert.Nil(t, err)
	plaintext3, err := bobRatchetState.ratchetDecrypt(header3, ciphertext3, ad)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, plaintext3)

	// メッセージが送れてきた
	plaintext2, err := bobRatchetState.ratchetDecrypt(header2, ciphertext2, ad)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, plaintext2)
}
