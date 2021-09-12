package e2ee

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type messageHeader struct {
	packetType uint8
	reserved   uint8
	// 0 もありえる
	ciphertextLength uint16
}

func decodeMessageHeader(data []byte) (*messageHeader, *bytes.Reader, error) {
	if len(data) < 4 {
		// パケットが 4 バイト以下なのでパースできない
		return nil, nil, errors.New("invalid data")
	}

	h := &messageHeader{}
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.BigEndian, &h.packetType); err != nil {
		return nil, nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &h.reserved); err != nil {
		return nil, nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &h.ciphertextLength); err != nil {
		return nil, nil, err
	}

	return h, buf, nil
}

// ```erlang
// <<?E2EE_PRE_KEY_MESSAGE_TYPE:8, Reserved:8, CiphertextLength:16,
//   SrcConnectionID:26/binary, DstConnectionID:26/binary,
//   IdentityKey:32/binary, EphemeralKey:32/binary>>
// ```

type preKeyMessage struct {
	selfConnectionID   [26]byte
	remoteConnectionID [26]byte
	// ここで渡す identityKey は ed25519
	identityKey  [32]byte
	ephemeralKey x25519PublicKey
}

func decodePreKeyMessage(header messageHeader, buf *bytes.Reader) (*preKeyMessage, error) {
	m := &preKeyMessage{}

	if err := binary.Read(buf, binary.BigEndian, &m.selfConnectionID); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.remoteConnectionID); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.identityKey); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.ephemeralKey); err != nil {
		return nil, err
	}

	return m, nil
}

// <<?E2EE_CIPHER_MESSAGE_TYPE:8, Reserved:8, CiphertextLength:16,
//   SrcConnectionID:26/binary, DstConnectionID:26/binary,
//   ## CipherMessage のここはヘッダー
//   RachetKey:32/binary, N:32, NP:32,
//   ## 本体
//   Ciphertext/binary>>

// Ciphertext 中身
// <<KeyId:32, SecretKeyMaterial:32/binary>>

type cipherMessage struct {
	selfConnectionID   [26]byte
	remoteConnectionID [26]byte
	ratchetKey         x25519PublicKey
	PN                 uint32
	N                  uint32
	ciphertext         []byte
}

func decodeCipherMessage(header messageHeader, buf *bytes.Reader) (*cipherMessage, error) {
	m := &cipherMessage{}

	if err := binary.Read(buf, binary.BigEndian, &m.selfConnectionID); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.remoteConnectionID); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.ratchetKey); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.PN); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.N); err != nil {
		return nil, err
	}

	var ciphertext = make([]byte, header.ciphertextLength)

	if err := binary.Read(buf, binary.BigEndian, ciphertext); err != nil {
		return nil, err
	}

	m.ciphertext = ciphertext

	return m, nil
}

// ciphertext の中身
type senderKeyMessage struct {
	keyID             uint32
	secretKeyMaterial [32]byte
}

func decodeSenderKeyMessage(plaintext []byte) (*senderKeyMessage, error) {
	buf := bytes.NewReader(plaintext)
	m := &senderKeyMessage{}

	if err := binary.Read(buf, binary.BigEndian, &m.keyID); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &m.secretKeyMaterial); err != nil {
		return nil, err
	}

	return m, nil
}
