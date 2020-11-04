package e2ee

import (
	"crypto/ed25519"
	"encoding/base64"
	"syscall/js"

	"errors"
	"fmt"
)

type remoteSecretKeyMaterial struct {
	keyID             uint32
	secretKeyMaterial []byte
}

// js にわたすための変換前の処理
type startSessionResult struct {
	selfConnectionID         string
	selfKeyID                uint32
	selfSecretKeyMaterial    []byte
	remoteSecretKeyMaterials map[string]remoteSecretKeyMaterial
	messages                 [][]byte
}

type stopSessionResult struct {
	selfConnectionID      string
	selfKeyID             uint32
	selfSecretKeyMaterial []byte
	messages              [][]byte
}

type receiveMessageResult struct {
	remoteSecretKeyMaterials map[string]remoteSecretKeyMaterial
	messages                 [][]byte
}

const (
	connectionIDLength = 26
)

// RegisterCallbacks ...
func RegisterCallbacks(version string) {
	s, err := initE2EE(version)
	if err != nil {
		// TODO(v): ここはどうするか考える
		panic(err)
	}
	js.Global().Set("e2ee", js.ValueOf(
		map[string]interface{}{
			"init":               js.FuncOf(s.wasmInitE2EE),
			"version":            js.FuncOf(s.wasmVersion),
			"start":              js.FuncOf(s.wasmStartE2EE),
			"startSession":       js.FuncOf(s.wasmStartSession),
			"stopSession":        js.FuncOf(s.wasmStopSession),
			"receiveMessage":     js.FuncOf(s.wasmReceiveMessage),
			"addPreKeyBundle":    js.FuncOf(s.wasmAddPreKeyBundle),
			"selfFingerprint":    js.FuncOf(s.wasmSelfFingerprint),
			"remoteFingerprints": js.FuncOf(s.wasmRemoteFingerprints),
		},
	))
}

func (e *e2ee) wasmVersion(this js.Value, args []js.Value) interface{} {
	return e.getVersion()
}

func (e *e2ee) wasmInitE2EE(this js.Value, args []js.Value) interface{} {
	selfPreKeyBundle := e.init()
	return map[string]interface{}{
		"preKeyBundle": selfPreKeyBundle.toJsValue(),
	}
}

func (e *e2ee) wasmStartE2EE(this js.Value, args []js.Value) interface{} {
	// TODO(v): バリデーション
	selfConnectionID := args[0].String()
	if len(selfConnectionID) != connectionIDLength {
		return toJsReturnValue(nil, jsError(errors.New("UnexpectedSelfConnectionIDError")))
	}
	secretKeyMaterial := e.start(selfConnectionID)

	result := map[string]interface{}{
		"selfKeyId":             e.keyID,
		"selfSecretKeyMaterial": bytesToUint8Array(secretKeyMaterial),
	}
	return toJsReturnValue(result, nil)
}

func (p preKeyBundle) toJsValue() map[string]interface{} {
	base64edIdentityKey := base64.StdEncoding.EncodeToString(p.identityKey)
	base64edSignedPreKey := base64.StdEncoding.EncodeToString(p.signedPreKey[:])
	base64edPreKeySignature := base64.StdEncoding.EncodeToString(p.preKeySignature)

	return map[string]interface{}{
		"identityKey":     base64edIdentityKey,
		"signedPreKey":    base64edSignedPreKey,
		"preKeySignature": base64edPreKeySignature,
	}

}

func (e *e2ee) wasmStartSession(this js.Value, args []js.Value) interface{} {
	// 相手の connectionID を追加
	remoteConnectionID := args[0].String()
	if len(remoteConnectionID) != connectionIDLength {
		return toJsReturnValue(nil, jsError(errors.New("UnexpectedRemoteConnectionIDError")))
	}

	base64edIdentityKey := args[1].String()
	identityKey, err := base64.StdEncoding.DecodeString(base64edIdentityKey)
	if err != nil {
		return toJsReturnValue(nil, jsError(err))
	}

	base64edSignedPreKey := args[2].String()
	signedPreKey, err := base64.StdEncoding.DecodeString(base64edSignedPreKey)
	if err != nil {
		return toJsReturnValue(nil, jsError(err))
	}

	base64edPreKeySignature := args[3].String()
	preKeySignature, err := base64.StdEncoding.DecodeString(base64edPreKeySignature)
	if err != nil {
		return toJsReturnValue(nil, jsError(err))
	}

	// ここじゃなくてもいい気はする
	var copySignedPreKey [32]byte
	copy(copySignedPreKey[:], signedPreKey)

	ok := ed25519.Verify(identityKey, signedPreKey, preKeySignature)
	if !ok {
		return toJsReturnValue(nil, jsError(errors.New("VerifyFailedError")))
	}

	preKeyBundle := &preKeyBundle{
		identityKey:     identityKey,
		signedPreKey:    copySignedPreKey,
		preKeySignature: preKeySignature,
	}

	result, err := e.startSession(remoteConnectionID, *preKeyBundle)
	if err != nil {
		return toJsReturnValue(nil, jsError(err))
	}

	return toJsReturnValue(result.toJsValue(), nil)
}

func (e *e2ee) wasmStopSession(this js.Value, args []js.Value) interface{} {
	remoteConnectionID := args[0].String()
	if len(remoteConnectionID) != connectionIDLength {
		return toJsReturnValue(nil, jsError(errors.New("UnexpectedRemoteConnectionIDError")))
	}

	result, err := e.stopSession(remoteConnectionID)
	if err != nil {
		return toJsReturnValue(nil, jsError(err))
	}

	return toJsReturnValue(result.toJsValue(), nil)
}

func (e *e2ee) wasmReceiveMessage(this js.Value, args []js.Value) interface{} {
	data := make([]byte, args[0].Get("length").Int())
	_ = js.CopyBytesToGo(data, args[0])

	result, err := e.receiveMessage(data)
	if err != nil {
		return toJsReturnValue(nil, jsError(err))
	}

	return toJsReturnValue(result.toJsValue(), nil)
}

func (e *e2ee) wasmAddPreKeyBundle(this js.Value, args []js.Value) interface{} {
	remoteConnectionID := args[0].String()
	if len(remoteConnectionID) != connectionIDLength {
		return jsError(errors.New("UnexpectedRemoteConnectionIDError"))
	}

	base64edIdentityKey := args[1].String()
	identityKey, err := base64.StdEncoding.DecodeString(base64edIdentityKey)
	if err != nil {
		return jsError(err)
	}

	base64edSignedPreKey := args[2].String()
	signedPreKey, err := base64.StdEncoding.DecodeString(base64edSignedPreKey)
	if err != nil {
		return jsError(err)
	}

	base64edPreKeySignature := args[3].String()
	preKeySignature, err := base64.StdEncoding.DecodeString(base64edPreKeySignature)
	if err != nil {
		return jsError(err)
	}

	// ここじゃなくてもいい気はする
	var copySignedPreKey [32]byte
	copy(copySignedPreKey[:], signedPreKey)

	ok := ed25519.Verify(identityKey, signedPreKey, preKeySignature)
	if !ok {
		return jsError(errors.New("VerifyFailedError"))
	}

	preKeyBundle := &preKeyBundle{
		identityKey:     identityKey,
		signedPreKey:    copySignedPreKey,
		preKeySignature: preKeySignature,
	}

	if err := e.addPreKeyBundle(remoteConnectionID, *preKeyBundle); err != nil {
		return jsError(err)
	}

	return nil
}

func (e *e2ee) wasmSelfFingerprint(this js.Value, args []js.Value) interface{} {
	return e.selfFingerprint()
}

func (e *e2ee) wasmRemoteFingerprints(this js.Value, args []js.Value) interface{} {
	remoteFingerprints := make(map[string]interface{})
	for connectionID, fingerprint := range e.remoteFingerprints() {
		remoteFingerprints[connectionID] = fingerprint
	}
	return remoteFingerprints
}

func (r startSessionResult) toJsValue() map[string]interface{} {
	secretKeyMaterials := make(map[string]interface{})
	for connectionID, v := range r.remoteSecretKeyMaterials {
		secretKeyMaterials[connectionID] = map[string]interface{}{
			"keyId":             v.keyID,
			"secretKeyMaterial": bytesToUint8Array(v.secretKeyMaterial),
		}
	}

	var messages []interface{}
	for _, s := range r.messages {
		messages = append(messages, bytesToUint8Array(s))
	}

	return map[string]interface{}{
		"selfConnectionId":         r.selfConnectionID,
		"selfKeyId":                r.selfKeyID,
		"selfSecretKeyMaterial":    bytesToUint8Array(r.selfSecretKeyMaterial),
		"remoteSecretKeyMaterials": secretKeyMaterials,
		"messages":                 messages,
	}
}

func (r stopSessionResult) toJsValue() map[string]interface{} {
	var messages []interface{}
	for _, s := range r.messages {
		messages = append(messages, bytesToUint8Array(s))
	}

	return map[string]interface{}{
		"selfConnectionId":      r.selfConnectionID,
		"selfKeyId":             r.selfKeyID,
		"selfSecretKeyMaterial": bytesToUint8Array(r.selfSecretKeyMaterial),
		"messages":              messages,
	}
}

func (r receiveMessageResult) toJsValue() map[string]interface{} {
	secretKeyMaterials := make(map[string]interface{})
	for connectionID, v := range r.remoteSecretKeyMaterials {
		secretKeyMaterials[connectionID] = map[string]interface{}{
			"keyId":             v.keyID,
			"secretKeyMaterial": bytesToUint8Array(v.secretKeyMaterial),
		}
	}

	var messages []interface{}
	for _, s := range r.messages {
		messages = append(messages, bytesToUint8Array(s))
	}

	return map[string]interface{}{
		"remoteSecretKeyMaterials": secretKeyMaterials,
		"messages":                 messages,
	}
}

func bytesToUint8Array(data []byte) js.Value {
	d := js.Global().Get("Uint8Array").New(len(data))
	_ = js.CopyBytesToJS(d, data)

	return d
}

// エラーも js に返すため [jsValue, error] へ
func toJsReturnValue(jsValue, err interface{}) []interface{} {
	if jsValue == nil {
		jsValue = js.Undefined()
	}
	if err == nil {
		err = js.Undefined()
	}

	return []interface{}{jsValue, err}
}

// error を js の Error オブジェクトへ
func jsError(err error) js.Value {
	return js.Global().Get("Error").New(err.Error())
}

// console にエラーを表示させる
// TODO: デバッグ用のため、不要な場合は削除する
func jsConsole(level, format string, args ...interface{}) {
	js.Global().Get("console").Call(level, fmt.Sprintf(format, args...))
}
