package e2ee

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCrypto(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	ad := make([]byte, 64)
	plaintext := []byte("1234560")

	ciphertext, err := encrypt(key, nonce, plaintext, ad)
	assert.Nil(t, err)

	newPlaintext, err := decrypt(key, nonce, ciphertext, ad)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, newPlaintext)
}
