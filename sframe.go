package e2ee

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SK = HKDF-SHA256(PreviousSK, "", "SFrameRatchetKey", 32)
func ratchetSecretKeyMaterial(secretKeyMaterial []byte) ([]byte, error) {
	hash := sha256.New
	salt := make([]byte, hash().Size())
	info := []byte("SFrameRatchetKey")
	hkdf := hkdf.New(hash, salt, secretKeyMaterial, info)

	newSecretKeyMaterial := make([]byte, 32)

	if _, err := io.ReadFull(hkdf, newSecretKeyMaterial); err != nil {
		return nil, err
	}

	return newSecretKeyMaterial, nil
}
