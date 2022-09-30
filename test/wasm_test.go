package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
)

const (
	wasmExecPath = "wasm_exec.js"
	wasmPath     = "wasm.wasm"

	aliceConnectionID = "ALICE---------------------"
	bobConnectionID   = "BOB-----------------------"
	carolConnectionID = "CAROL---------------------"
)

func NewWasmServer(wasmPath string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/" {
			html := fmt.Sprintf(`<html>
	<head>
		<script src="%s"></script>
		<script>
			const go = new Go();
			WebAssembly.instantiateStreaming(fetch("%s"), go.importObject)
			.then((result) => {
				go.run(result.instance);
			})
			.then(() => {
			})
		</script>
	</head>
</html>`, wasmExecPath, wasmPath)
			fmt.Fprintln(w, html)
		} else {
			// 静的ファイル
			filePath := r.URL.Path[1:]
			http.ServeFile(w, r, filePath)
		}
	}))
}

func TestWasm(t *testing.T) {
	assert := assert.New(t)

	s := NewWasmServer(wasmPath)
	defer s.Close()

	url := fmt.Sprintf("%s", s.URL)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Headless,
	}...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
	)

	// TODO: 型の確認

	r := run(ctx, "version = E2EE.version()")
	assert.Equal("2020.2.1", r)

	r1 := run(ctx, "alice = new E2EE()")
	assert.NotNil(r1)

	r2 := run(ctx, "bob = new E2EE()")
	assert.NotNil(r2)

	// ALICE 用
	r3 := run(ctx, "alicePreKeyBundle = (() => alice.init())().preKeyBundle")
	alicePreKeyBundle := r3.(map[string]interface{})
	assert.NotEmpty(alicePreKeyBundle["identityKey"].(string))
	assert.NotEmpty(alicePreKeyBundle["signedPreKey"].(string))
	assert.NotEmpty(alicePreKeyBundle["preKeySignature"].(string))

	// BOB 用
	r4 := run(ctx, "bobPreKeyBundle = (() => bob.init())().preKeyBundle")
	bobPreKeyBundle := r4.(map[string]interface{})
	assert.NotEmpty(bobPreKeyBundle["identityKey"].(string))
	assert.NotEmpty(bobPreKeyBundle["signedPreKey"].(string))
	assert.NotEmpty(bobPreKeyBundle["preKeySignature"].(string))

	// [result, error]
	r5 := run(ctx, "alice.start('%s')", aliceConnectionID)
	assert.Nil(r5.([]interface{})[1])
	aliceResult1 := r5.([]interface{})[0].(map[string]interface{})
	// Number は int ではなく float
	assert.Equal(0.0, aliceResult1["selfKeyId"].(float64))
	assert.Equal(32, len(aliceResult1["selfSecretKeyMaterial"].(map[string]interface{})))

	// [result, error]
	r6 := run(ctx, "bob.start('%s')", bobConnectionID)
	assert.Nil(r6.([]interface{})[1])
	bobResult1 := r6.([]interface{})[0].(map[string]interface{})
	assert.Equal(0.0, bobResult1["selfKeyId"].(float64))
	assert.Equal(32, len(bobResult1["selfSecretKeyMaterial"].(map[string]interface{})))

	// [result, error]
	r7 := run(ctx, "[aliceResult1, err] = alice.startSession('%s', bobPreKeyBundle.identityKey, bobPreKeyBundle.signedPreKey, bobPreKeyBundle.preKeySignature)", bobConnectionID)
	assert.NotNil(r7)
	assert.Nil(r7.([]interface{})[1])
	aliceResult2 := r7.([]interface{})[0].(map[string]interface{})
	assert.NotNil(aliceResult2["remoteSecretKeyMaterials"].(map[string]interface{}))
	assert.Equal(0, len(aliceResult2["remoteSecretKeyMaterials"].(map[string]interface{})))
	assert.Equal(2, len(aliceResult2["messages"].([]interface{})))
	assert.Equal(1.0, aliceResult2["selfKeyId"])
	assert.Equal(aliceConnectionID, aliceResult2["selfConnectionId"])

	// null / undefined は許容されないため、err がない場合は文字列を返す
	r8 := run(ctx, "bob.addPreKeyBundle('%s', alicePreKeyBundle.identityKey, alicePreKeyBundle.signedPreKey, alicePreKeyBundle.preKeySignature) || 'NO-ERROR'", aliceConnectionID)
	assert.Equal("NO-ERROR", r8.(string))

	// [result, error]
	r9 := run(ctx, "bob.receiveMessage(aliceResult1.messages[0])")
	assert.Nil(r9.([]interface{})[1])
	bobResult2 := r9.([]interface{})[0].(map[string]interface{})
	assert.Equal(0, len(bobResult2["remoteSecretKeyMaterials"].(map[string]interface{})))
	assert.Equal(0, len(bobResult2["messages"].([]interface{})))

	// [result, error]
	r10 := run(ctx, "[bobResult1, err] = bob.receiveMessage(aliceResult1.messages[1])")
	assert.Nil(r10.([]interface{})[1])
	bobResult3 := r10.([]interface{})[0].(map[string]interface{})
	bobRemoteSecretKeyMaterials3 := bobResult3["remoteSecretKeyMaterials"].(map[string]interface{})
	assert.Equal(1, len(bobRemoteSecretKeyMaterials3))
	assert.Equal(1, len(bobResult3["messages"].([]interface{})))
	assert.Equal(1.0, bobRemoteSecretKeyMaterials3[aliceConnectionID].(map[string]interface{})["keyId"].(float64))

	// [result, error]
	r11 := run(ctx, "alice.receiveMessage(bobResult1.messages[0])")
	assert.Nil(r11.([]interface{})[1])
	aliceResult3 := r11.([]interface{})[0].(map[string]interface{})
	assert.Equal(0, len(aliceResult3["messages"].([]interface{})))
	aliceRemoteSecretKeyMaterials3 := aliceResult3["remoteSecretKeyMaterials"].(map[string]interface{})
	assert.Equal(1, len(aliceRemoteSecretKeyMaterials3))
	assert.Equal(0.0, aliceRemoteSecretKeyMaterials3[bobConnectionID].(map[string]interface{})["keyId"].(float64))

	// CAROL 追加
	r12 := run(ctx, "carol = new E2EE()")
	assert.NotNil(r12)

	r13 := run(ctx, "carolPreKeyBundle = (() => carol.init())().preKeyBundle")
	carolPreKeyBundle := r13.(map[string]interface{})
	assert.NotEmpty(carolPreKeyBundle["identityKey"].(string))
	assert.NotEmpty(carolPreKeyBundle["signedPreKey"].(string))
	assert.NotEmpty(carolPreKeyBundle["preKeySignature"].(string))

	// [result, error]
	r14 := run(ctx, "carol.start('%s')", carolConnectionID)
	carolResult1 := r14.([]interface{})[0].(map[string]interface{})
	assert.Nil(r14.([]interface{})[1])
	// Number は int ではなく float
	assert.Equal(0.0, carolResult1["selfKeyId"].(float64))
	assert.Equal(32, len(carolResult1["selfSecretKeyMaterial"].(map[string]interface{})))

	r15 := run(ctx, "carol.addPreKeyBundle('%s', alicePreKeyBundle.identityKey, alicePreKeyBundle.signedPreKey, alicePreKeyBundle.preKeySignature) || 'NO-ERROR'", aliceConnectionID)
	assert.Equal("NO-ERROR", r15.(string))

	r16 := run(ctx, "carol.addPreKeyBundle('%s', bobPreKeyBundle.identityKey, bobPreKeyBundle.signedPreKey, bobPreKeyBundle.preKeySignature) || 'NO-ERROR'", bobConnectionID)
	assert.Equal("NO-ERROR", r16.(string))

	// [result, error]
	r17 := run(ctx, "[aliceResult2, err] = alice.startSession('%s', carolPreKeyBundle.identityKey, carolPreKeyBundle.signedPreKey, carolPreKeyBundle.preKeySignature)", carolConnectionID)
	assert.NotNil(r17)
	assert.Nil(r17.([]interface{})[1])
	aliceResult4 := r17.([]interface{})[0].(map[string]interface{})
	assert.NotNil(aliceResult4["remoteSecretKeyMaterials"].(map[string]interface{}))
	assert.Equal(2, len(aliceResult4["messages"].([]interface{})))
	assert.Equal(2.0, aliceResult4["selfKeyId"])
	assert.Equal(aliceConnectionID, aliceResult4["selfConnectionId"])

	// [result, error]
	r18 := run(ctx, "carol.receiveMessage(aliceResult2.messages[0])")
	assert.Nil(r18.([]interface{})[1])
	carolResult2 := r18.([]interface{})[0].(map[string]interface{})
	assert.Equal(0, len(carolResult2["remoteSecretKeyMaterials"].(map[string]interface{})))
	assert.Equal(0, len(carolResult2["messages"].([]interface{})))

	// [result, error]
	r19 := run(ctx, "[carolResult1, err] = carol.receiveMessage(aliceResult2.messages[1])")
	assert.Nil(r19.([]interface{})[1])
	carolResult3 := r19.([]interface{})[0].(map[string]interface{})
	assert.Equal(1, len(carolResult3["remoteSecretKeyMaterials"].(map[string]interface{})))
	assert.Equal(1, len(carolResult3["messages"].([]interface{})))

	// [result, error]
	r20 := run(ctx, "[bobResult2, err] = bob.startSession('%s', carolPreKeyBundle.identityKey, carolPreKeyBundle.signedPreKey, carolPreKeyBundle.preKeySignature)", carolConnectionID)
	assert.NotNil(r20)
	assert.Nil(r20.([]interface{})[1])
	bobResult4 := r20.([]interface{})[0].(map[string]interface{})
	assert.NotNil(bobResult4["remoteSecretKeyMaterials"].(map[string]interface{}))
	assert.Equal(2, len(bobResult4["messages"].([]interface{})))
	assert.Equal(1.0, bobResult4["selfKeyId"])
	assert.Equal(bobConnectionID, bobResult4["selfConnectionId"])

	// [result, error]
	r21 := run(ctx, "carol.receiveMessage(bobResult2.messages[0])")
	assert.Nil(r21.([]interface{})[1])
	carolResult4 := r21.([]interface{})[0].(map[string]interface{})
	assert.Equal(0, len(carolResult4["remoteSecretKeyMaterials"].(map[string]interface{})))
	assert.Equal(0, len(carolResult4["messages"].([]interface{})))

	// [result, error]
	r22 := run(ctx, "[carolResult2, err] = carol.receiveMessage(bobResult2.messages[1])")
	assert.Nil(r22.([]interface{})[1])
	carolResult5 := r22.([]interface{})[0].(map[string]interface{})
	assert.Equal(1, len(carolResult5["remoteSecretKeyMaterials"].(map[string]interface{})))
	assert.Equal(1, len(carolResult5["messages"].([]interface{})))

	// [result, error]
	r23 := run(ctx, "alice.receiveMessage(carolResult1.messages[0])")
	assert.Nil(r23.([]interface{})[1])
	aliceResult5 := r23.([]interface{})[0].(map[string]interface{})
	aliceRemoteSecretKeyMaterials5 := aliceResult5["remoteSecretKeyMaterials"].(map[string]interface{})
	assert.Equal(0.0, aliceRemoteSecretKeyMaterials5[carolConnectionID].(map[string]interface{})["keyId"].(float64))
	assert.Equal(0, len(aliceResult5["messages"].([]interface{})))

	// [result, error]
	r24 := run(ctx, "bob.receiveMessage(carolResult2.messages[0])")
	assert.Nil(r24.([]interface{})[1])
	bobResult5 := r24.([]interface{})[0].(map[string]interface{})
	bobRemoteSecretKeyMaterials5 := bobResult5["remoteSecretKeyMaterials"].(map[string]interface{})
	assert.Equal(0.0, bobRemoteSecretKeyMaterials5[carolConnectionID].(map[string]interface{})["keyId"].(float64))
	assert.Equal(0, len(bobResult5["messages"].([]interface{})))

	// [result, error]
	r25 := run(ctx, "[aliceResult3, err] = alice.stopSession('%s')", carolConnectionID)
	assert.Nil(r25.([]interface{})[1])
	aliceResult6 := r25.([]interface{})[0].(map[string]interface{})
	assert.Equal(1, len(aliceResult6["messages"].([]interface{})))
	assert.Equal(3.0, aliceResult6["selfKeyId"])
	assert.Equal(aliceConnectionID, aliceResult6["selfConnectionId"])

	// [result, error]
	r26 := run(ctx, "[bobResult3, err] = bob.stopSession('%s')", carolConnectionID)
	assert.Nil(r26.([]interface{})[1])
	bobResult6 := r26.([]interface{})[0].(map[string]interface{})
	assert.Equal(1, len(bobResult6["messages"].([]interface{})))
	assert.Equal(2.0, bobResult6["selfKeyId"])
	assert.Equal(bobConnectionID, bobResult6["selfConnectionId"])

	// [result, error]
	r27 := run(ctx, "alice.receiveMessage(bobResult3.messages[0])")
	assert.Nil(r27.([]interface{})[1])
	aliceResult7 := r27.([]interface{})[0].(map[string]interface{})
	assert.Equal(0, len(aliceResult7["messages"].([]interface{})))

	// [result, error]
	r28 := run(ctx, "bob.receiveMessage(aliceResult3.messages[0])")
	assert.Nil(r28.([]interface{})[1])
	bobResult7 := r28.([]interface{})[0].(map[string]interface{})
	assert.Equal(0, len(bobResult7["messages"].([]interface{})))

	chromedp.Run(ctx,
		chromedp.Stop(),
	)
}

// TODO: option 指定の追加
func run(ctx context.Context, format string, args ...interface{}) interface{} {
	var res interface{}
	script := fmt.Sprintf(format, args...)
	// fmt.Printf("%s;\n", script)
	err := chromedp.Run(ctx,
		chromedp.Evaluate(script, &res),
	)

	if err != nil {
		panic(err)
	}

	return res
}
