package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

type e2ee struct {
	// このライブラリのバージョン
	version string

	// 自分
	keyID             uint32
	secretKeyMaterial []byte
	connectionID      string

	// TODO(v): self をつけるかどうか考える
	identityKeyPair ed25519KeyPair
	preKeyPair      x25519KeyPair

	selfPreKeyBundle preKeyBundle

	remotePreKeyBundles map[string]preKeyBundle
	sessions            map[string]session
}

func newE2EE(version string) *e2ee {
	return &e2ee{version: version}
}

func (e *e2ee) getVersion() string {
	return e.version
}

func (e *e2ee) selfFingerprint() string {
	return fingerprint(e.identityKeyPair.publicKey)
}

func (e *e2ee) remoteFingerprints() map[string]string {
	remoteIdentityKeyFingerprints := make(map[string]string)
	for remoteConnectionID, remotePreKeyBundle := range e.remotePreKeyBundles {
		fingerprint := fingerprint(remotePreKeyBundle.identityKey)
		remoteIdentityKeyFingerprints[remoteConnectionID] = fingerprint
	}
	return remoteIdentityKeyFingerprints
}

func generateSecretKeyMaterial() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (e *e2ee) init() error {
	secretKeyMaterial, err := generateSecretKeyMaterial()
	if err != nil {
		return err
	}

	identityKeyPair, err := generateEd25519KeyPair()
	if err != nil {
		return err
	}
	preKeyPair, err := generateX25519KeyPair()
	if err != nil {
		return err
	}

	selfPreKeyBundle := generatePreKeyBundle(*identityKeyPair, *preKeyPair)

	e.keyID = 0
	e.secretKeyMaterial = secretKeyMaterial
	e.connectionID = ""

	e.identityKeyPair = *identityKeyPair
	e.preKeyPair = *preKeyPair

	e.selfPreKeyBundle = *selfPreKeyBundle

	e.remotePreKeyBundles = make(map[string]preKeyBundle)
	e.sessions = make(map[string]session)

	return nil
}

func (e *e2ee) start(selfConnectionID string) []byte {
	e.connectionID = selfConnectionID
	return e.secretKeyMaterial
}

// TODO(v): 関数名前がひどい
func (e *e2ee) plaintext() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, e.keyID); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, e.secretKeyMaterial); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *e2ee) messages() ([][]byte, error) {
	var index = 0
	messages := make([][]byte, len(e.sessions))
	for cid, session := range e.sessions {
		// 全員に送る CipherMessage を生成する
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.BigEndian, e.keyID); err != nil {
			return nil, err
		}

		if err := binary.Write(buf, binary.BigEndian, e.secretKeyMaterial); err != nil {
			return nil, err
		}

		header, ciphertext, err := session.ratchetState.ratchetEncrypt(buf.Bytes(), session.ad)
		if err != nil {
			return nil, err
		}

		message, err := session.cipherMessage(header, ciphertext)
		if err != nil {
			return nil, err
		}

		e.sessions[cid] = session
		messages[index] = message
		index++
	}

	return messages, nil
}

func (e *e2ee) startSession(remoteConnectionID string, identityKey, signedPreKey, preKeySignature []byte) (*startSessionResult, error) {
	// セッションがすでに無いかどうかの確認をする
	_, ok := e.sessions[remoteConnectionID]
	if ok {
		// すでにセッションがあるのに呼んでるのでエラーにする
		// いい名前のエラーが必要
		return nil, errors.New("SessionAlreadyExists")
	}

	// すでに持っている preKeyBundle だったらエラーを返す
	if err := e.addPreKeyBundle(remoteConnectionID, identityKey, signedPreKey, preKeySignature); err != nil {
		return nil, err
	}

	var copySignedPreKey [32]byte
	copy(copySignedPreKey[:], signedPreKey)

	preKeyBundle := &preKeyBundle{
		identityKey:     identityKey,
		signedPreKey:    copySignedPreKey,
		preKeySignature: preKeySignature,
	}

	// secretMaterialKey の更新が必要
	session, err := e.initSession(remoteConnectionID, *preKeyBundle)
	if err != nil {
		return nil, err
	}

	// start 側が sender になる
	session.role = sender
	if err := session.senderRootKey(); err != nil {
		return nil, err
	}
	if err := session.senderRatchetInit(session.rootKey, *preKeyBundle); err != nil {
		return nil, err
	}

	var remoteSecretKeyMaterials = make(map[string]remoteSecretKeyMaterial)

	// ここで startSesson 以外のセッションの SK を更新する
	for cid, s := range e.sessions {
		s.ratchetSecretKeymaterial()

		remoteKeyMaterial := &remoteSecretKeyMaterial{
			keyID:             s.remoteKeyID,
			secretKeyMaterial: s.remoteSecretKeyMaterial,
		}

		remoteSecretKeyMaterials[cid] = *remoteKeyMaterial

		// セッション更新して代入
		e.sessions[cid] = s
	}

	// startSession はここで追加する
	e.sessions[remoteConnectionID] = *session

	// ここで自分の SK を更新する
	newSecretKeyMaterial, err := ratchetSecretKeyMaterial(e.secretKeyMaterial)
	if err != nil {
		return nil, err
	}
	e.secretKeyMaterial = newSecretKeyMaterial
	// SK 更新したので KeyIdentifier をインクリメントする
	e.keyID++

	preKeyMessage, err := session.preKeyMessage()
	if err != nil {
		return nil, err
	}

	// selfKeyId + selfSecretKeyMaterial
	plaintext, err := e.plaintext()
	if err != nil {
		return nil, err
	}

	header, ciphertext, err := session.ratchetState.ratchetEncrypt(plaintext, session.ad)
	if err != nil {
		return nil, err
	}

	ratchetMessage, err := session.cipherMessage(header, ciphertext)
	if err != nil {
		return nil, err
	}

	return &startSessionResult{
		selfConnectionID:         e.connectionID,
		selfKeyID:                e.keyID,
		selfSecretKeyMaterial:    e.secretKeyMaterial,
		remoteSecretKeyMaterials: remoteSecretKeyMaterials,
		messages:                 [][]byte{preKeyMessage, ratchetMessage},
	}, nil
}

func (e *e2ee) stopSession(remoteConnectionID string) (*stopSessionResult, error) {
	_, ok := e.sessions[remoteConnectionID]
	if !ok {
		return nil, errors.New("MissingSessionError")
	}
	delete(e.sessions, remoteConnectionID)

	_, ok = e.remotePreKeyBundles[remoteConnectionID]
	if !ok {
		return nil, errors.New("MissingPreKeyBundleError")
	}
	delete(e.remotePreKeyBundles, remoteConnectionID)

	// 新しく SK を生成する
	newSecretKeyMaterial, err := generateSecretKeyMaterial()
	if err != nil {
		return nil, err
	}
	e.secretKeyMaterial = newSecretKeyMaterial
	e.keyID++

	messages, err := e.messages()
	if err != nil {
		return nil, err
	}

	return &stopSessionResult{
		selfConnectionID:      e.connectionID,
		selfKeyID:             e.keyID,
		selfSecretKeyMaterial: e.secretKeyMaterial,
		messages:              messages,
	}, nil
}

const (
	typePreKeyMessage uint8 = 0
	typeCipherMessage uint8 = 1
)

// preKeyMessage または cipherMessage
// cid, sk, msgs, err
func (e *e2ee) receiveMessage(data []byte) (*receiveMessageResult, error) {
	header, buf, err := decodeMessageHeader(data)
	if err != nil {
		return nil, errors.New("ReceiveMessageDecodeError")
	}

	switch header.packetType {
	case typePreKeyMessage:
		// この m, err の m を使う
		m, err := decodePreKeyMessage(*header, buf)
		if err != nil {
			return nil, err
		}
		result, err := e.preKeyMessage(*m)
		if err != nil {
			return nil, err
		}
		return result, nil
	case typeCipherMessage:
		m, err := decodeCipherMessage(*header, buf)
		if err != nil {
			return nil, err
		}
		result, err := e.cipherMessage(*m)
		if err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, errors.New("UnknownMessageError")
	}
}

func (e *e2ee) addPreKeyBundle(connectionID string, identityKey, signedPreKey, preKeySignature []byte) error {
	var copySignedPreKey [32]byte
	copy(copySignedPreKey[:], signedPreKey)

	ok := ed25519.Verify(identityKey, signedPreKey, preKeySignature)
	if !ok {
		return errors.New("VerifyFailedError")
	}

	preKeyBundle := &preKeyBundle{
		identityKey:     identityKey,
		signedPreKey:    copySignedPreKey,
		preKeySignature: preKeySignature,
	}

	_, ok = e.remotePreKeyBundles[connectionID]
	if ok {
		return errors.New("AlreadyExistRemotePreKeyBundle")
	}
	e.remotePreKeyBundles[connectionID] = *preKeyBundle
	return nil
}

func (e *e2ee) preKeyMessage(m preKeyMessage) (*receiveMessageResult, error) {
	// 相手が自分の ConnectionID を送ってきているので、リモートになる
	remoteConnectionID := string(m.selfConnectionID[:])

	preKeyBundle, ok := e.remotePreKeyBundles[remoteConnectionID]

	if !ok {
		return nil, errors.New("MissingRemotePreKeyBundle")
	}

	if !bytes.Equal(preKeyBundle.identityKey, m.identityKey[:]) {
		// metadata_list から取得した公開鍵と x3dh メッセージから取得した公開鍵が異なる
		return nil, errors.New("UnmatchIdentityKey")
	}

	// session, ok だけどそもそもセッションがあった時点で破棄する
	// メッセージを 2 回送ってきてる
	_, ok = e.sessions[remoteConnectionID]
	if !ok {
		newSession, err := e.initSession(remoteConnectionID, preKeyBundle)
		if err != nil {
			return nil, err
		}

		newSession.role = receiver
		newSession.remoteEphemeralKey = m.ephemeralKey

		newSession.receiverRootKey()
		newSession.receiverRatchetInit()

		e.sessions[remoteConnectionID] = *newSession

		// ここで相手に送るべきメッセージを生成する必要はない
		// cipherMessage メッセージを待つ
		return &receiveMessageResult{}, nil
	}

	return nil, errors.New("DiscardMessage")
}

func (e *e2ee) cipherMessage(m cipherMessage) (*receiveMessageResult, error) {
	remoteConnectionID := string(m.selfConnectionID[:])

	session, ok := e.sessions[remoteConnectionID]
	if !ok {
		// TODO(v): メッセージが入れ違った可能性があるので、どうするか考える
		return nil, errors.New("MissingSession")
	}

	header, err := cipherMessageHeader(m)
	if err != nil {
		return nil, err
	}

	plaintext, err := session.ratchetState.ratchetDecrypt(header, m.ciphertext, session.ad)
	if err != nil {
		return nil, err
	}
	senderKeyMessage, err := decodeSenderKeyMessage(plaintext)
	if err != nil {
		return nil, err
	}

	var remoteSecretKeyMaterials = make(map[string]remoteSecretKeyMaterial)
	var messages = [][]byte{}

	// receiver で 相手の SecretKeyMaterial を保持していない場合はメッセージを送る必要がある
	if session.role == receiver && bytes.Equal(session.remoteSecretKeyMaterial, []byte{}) {
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.BigEndian, e.keyID); err != nil {
			return nil, err
		}

		if err := binary.Write(buf, binary.BigEndian, e.secretKeyMaterial); err != nil {
			return nil, err
		}

		header, ciphertext, err := session.ratchetState.ratchetEncrypt(buf.Bytes(), session.ad)
		if err != nil {
			return nil, err
		}

		message, err := session.cipherMessage(header, ciphertext)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}

	session.remoteKeyID = senderKeyMessage.keyID
	session.remoteSecretKeyMaterial = senderKeyMessage.secretKeyMaterial[:]
	e.sessions[remoteConnectionID] = session

	remoteKeyMaterial := &remoteSecretKeyMaterial{
		keyID:             senderKeyMessage.keyID,
		secretKeyMaterial: senderKeyMessage.secretKeyMaterial[:],
	}

	remoteSecretKeyMaterials[remoteConnectionID] = *remoteKeyMaterial

	return &receiveMessageResult{
		remoteSecretKeyMaterials: remoteSecretKeyMaterials,
		messages:                 messages,
	}, nil
}

func (e *e2ee) initSession(remoteConnectionID string, preKeyBundle preKeyBundle) (*session, error) {
	// ここで相手の公開鍵の verify を行う
	ok := ed25519.Verify(preKeyBundle.identityKey, preKeyBundle.signedPreKey[:], preKeyBundle.preKeySignature)
	if !ok {
		return nil, errors.New("Ed25519VerifyError")
	}

	selfEphemeralKeyPair, err := generateEphemeralKeyPair()
	if err != nil {
		return nil, errors.New("X25519KeyPairGenerateError")
	}

	return &session{
		selfConnectionID:     e.connectionID,
		selfIdenityKeyPair:   e.identityKeyPair,
		selfPreKeyPair:       e.preKeyPair,
		selfEphemeralKeyPair: *selfEphemeralKeyPair,

		remoteConnectionID:          remoteConnectionID,
		remoteIdentityKey:           preKeyBundle.identityKey,
		remoteSignedPreKey:          preKeyBundle.signedPreKey,
		remoteSignedPreKeySignature: preKeyBundle.preKeySignature,
	}, nil
}
