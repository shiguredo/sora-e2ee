package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
)

func decrypt(key []byte, nonce []byte, ciphertext []byte, ad []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(c, len(nonce))
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func encrypt(key []byte, nonce []byte, plaintext []byte, ad []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(c, len(nonce))
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, ad)

	return ciphertext, nil
}
