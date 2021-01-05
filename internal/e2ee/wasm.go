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
	js.Global().Set("E2EE", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		e := newE2EE(version)
		this.Set("version", js.FuncOf(e.wasmVersion))
		this.Set("init", js.FuncOf(e.wasmInitE2EE))
		this.Set("start", js.FuncOf(e.wasmStartE2EE))
		this.Set("startSession", js.FuncOf(e.wasmStartSession))
		this.Set("stopSession", js.FuncOf(e.wasmStopSession))
		this.Set("receiveMessage", js.FuncOf(e.wasmReceiveMessage))
		this.Set("addPreKeyBundle", js.FuncOf(e.wasmAddPreKeyBundle))
		this.Set("selfFingerprint", js.FuncOf(e.wasmSelfFingerprint))
		this.Set("remoteFingerprints", js.FuncOf(e.wasmRemoteFingerprints))
		return js.Undefined()
	}))

	js.Global().Get("E2EE").Set("version", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return version
	}))

}

func (e *e2ee) wasmVersion(this js.Value, args []js.Value) interface{} {
	return e.getVersion()
}

func (e *e2ee) wasmInitE2EE(this js.Value, args []js.Value) interface{} {
	if err := e.init(); err != nil {
		// TODO(v): エラーメッセージを考える
		return toJsReturnValue(nil, jsError(errors.New("InitError")))
	}
	return map[string]interface{}{
		"preKeyBundle": e.selfPreKeyBundle.toJsValue(),
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

	result, err := e.startSession(remoteConnectionID, identityKey, signedPreKey, preKeySignature)
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
	return e.remoteFingerprints()
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
