package e2ee

import (
	"bytes"
	"encoding/binary"
)

type role uint

const (
	sender role = iota
	receiver
)

type session struct {
	role             role
	selfConnectionID string

	selfIdenityKeyPair   ed25519KeyPair
	selfPreKeyPair       x25519KeyPair
	selfEphemeralKeyPair x25519KeyPair

	remoteConnectionID      string
	remoteKeyID             uint32
	remoteSecretKeyMaterial []byte

	remoteIdentityKey           []byte
	remoteSignedPreKey          x25519PublicKey
	remoteSignedPreKeySignature []byte
	remoteEphemeralKey          x25519PublicKey

	// X3DH の戻り値
	rootKey []byte

	// senderPubKey, receiverPubKey をくっつけたやつ
	ad []byte

	ratchetState *ratchetState
}

func (s *session) x25519RemoteIdentityKey() (x25519PublicKey, error) {
	return publicEd25519KeyToCurve25519(s.remoteIdentityKey)
}

func (s *session) senderRootKey() error {
	remoteIdentityKey, err := s.x25519RemoteIdentityKey()
	if err != nil {
		return err
	}

	rootKey, err := senderRootKey(
		s.selfIdenityKeyPair.privateEd25519KeyToCurve25519(), s.selfEphemeralKeyPair.privateKey,
		remoteIdentityKey, s.remoteSignedPreKey)
	if err != nil {
		return err
	}

	s.rootKey = rootKey

	s.ad = append(s.selfIdenityKeyPair.publicKey, s.remoteIdentityKey...)

	return nil
}

func (s *session) receiverRootKey() error {
	remoteIdentityKey, err := s.x25519RemoteIdentityKey()
	if err != nil {
		return err
	}

	rootKey, err := receiverRootKey(
		s.selfIdenityKeyPair.privateEd25519KeyToCurve25519(), s.selfPreKeyPair.privateKey,
		remoteIdentityKey, s.remoteEphemeralKey)
	if err != nil {
		return err
	}

	s.rootKey = rootKey

	s.ad = append(s.remoteIdentityKey, s.selfIdenityKeyPair.publicKey...)

	return nil
}

func (s *session) senderRatchetInit(sk []byte, preKeyBundle preKeyBundle) error {
	ratchetState, err := senderRatchetInit(sk, preKeyBundle)
	if err != nil {
		return err
	}
	s.ratchetState = ratchetState

	return nil
}

func (s *session) receiverRatchetInit() {
	s.ratchetState = receiverRatchetInit(s.rootKey, s.selfPreKeyPair.publicKey, s.selfPreKeyPair.privateKey)
}

func (s *session) ratchetSecretKeymaterial() error {
	newRemoteSecretKeyMaterial, err := ratchetSecretKeyMaterial(s.remoteSecretKeyMaterial)
	if err != nil {
		return err
	}
	s.remoteKeyID++
	s.remoteSecretKeyMaterial = newRemoteSecretKeyMaterial

	return nil
}

func (s *session) preKeyMessage() ([]byte, error) {
	buf := new(bytes.Buffer)

	reserved := uint8(0)
	// 暗号メッセージサイズは 0 なので
	length := uint16(0)

	if err := binary.Write(buf, binary.BigEndian, typePreKeyMessage); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, reserved); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, length); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, []byte(s.selfConnectionID)); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, []byte(s.remoteConnectionID)); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, s.selfIdenityKeyPair.publicKey); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, s.selfEphemeralKeyPair.publicKey); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil

}

func (s *session) cipherMessage(ratchetHeader []byte, ciphertext []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	reserved := uint8(0)
	length := uint16(len(ciphertext))

	if err := binary.Write(buf, binary.BigEndian, typeCipherMessage); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, reserved); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, length); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, []byte(s.selfConnectionID)); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, []byte(s.remoteConnectionID)); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, ratchetHeader); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, ciphertext); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func cipherMessageHeader(m cipherMessage) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, m.ratchetKey); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, m.PN); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, m.N); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
