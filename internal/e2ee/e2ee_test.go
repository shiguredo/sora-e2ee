package e2ee

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestE2EEVersion(t *testing.T) {
	alice, err := initE2EE()
	assert.Nil(t, err)
	assert.NotNil(t, alice.version())
}

func TestE2EE(t *testing.T) {
	aliceConnectionID := "ALICE---------------------"
	bobConnectionID := "BOB-----------------------"

	alice, err := initE2EE()
	assert.Nil(t, err)
	assert.Equal(t, len(alice.secretKeyMaterial), 32)

	bob, err := initE2EE()
	assert.Nil(t, err)
	assert.Equal(t, len(bob.secretKeyMaterial), 32)

	alice.init()
	alice.start(aliceConnectionID)
	// 最初なので 0
	assert.Equal(t, uint32(0), alice.keyID)
	assert.NotNil(t, alice.selfFingerprint())
	assert.Empty(t, alice.remoteFingerprints())

	bob.init()
	bob.start(bobConnectionID)
	// 最初なので 0
	assert.Equal(t, uint32(0), bob.keyID)
	assert.NotNil(t, bob.selfFingerprint())
	assert.Empty(t, bob.remoteFingerprints())

	result, err := alice.startSession(bobConnectionID, bob.selfPreKeyBundle)
	assert.Nil(t, err)
	assert.NotEmpty(t, alice.remoteFingerprints())
	assert.Equal(t, 1, len(alice.remoteFingerprints()))
	// 新しく参加者が来たので sender の alice は keyId++ する
	assert.Equal(t, 2, len(result.messages))
	assert.Equal(t, uint32(1), result.selfKeyID)
	assert.Equal(t, aliceConnectionID, result.selfConnectionID)
	assert.Equal(t, uint32(1), alice.keyID)

	// まだ SK と keyID を相手からもらっていない
	_, ok := result.remoteSecretKeyMaterials[bobConnectionID]
	assert.False(t, ok)

	err = bob.addPreKeyBundle(aliceConnectionID, alice.selfPreKeyBundle)
	assert.Nil(t, err)
	assert.NotEmpty(t, bob.remoteFingerprints())
	assert.Equal(t, 1, len(bob.remoteFingerprints()))

	r0, err := bob.receiveMessage(result.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r0.remoteSecretKeyMaterials))
	assert.Equal(t, 0, len(r0.messages))
	// bob は reciever なので keyId++ しない
	assert.Equal(t, uint32(0), bob.keyID)

	// bob はまだ alice から sk をもらっていない
	_, ok = r0.remoteSecretKeyMaterials[aliceConnectionID]
	assert.False(t, ok)

	assert.Equal(t, alice.sessions[bobConnectionID].rootKey, bob.sessions[aliceConnectionID].rootKey)

	r1, err := bob.receiveMessage(result.messages[1])
	assert.Nil(t, err)
	assert.Equal(t, 1, len(r1.remoteSecretKeyMaterials))
	assert.Equal(t, 1, len(r1.messages))
	assert.Equal(t, uint32(0), bob.keyID)
	// alice の keyID は bob が参加したことにより sk が ratchet してるので 1
	assert.Equal(t, uint32(1), r1.remoteSecretKeyMaterials[aliceConnectionID].keyID)

	r2, err := alice.receiveMessage(r1.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 1, len(r2.remoteSecretKeyMaterials))
	assert.Equal(t, 0, len(r2.messages))
	assert.Equal(t, uint32(1), alice.keyID)
	// bob は新規参加者なので sk を ratchet してないので keyID は 0 のまま
	assert.Equal(t, uint32(0), r2.remoteSecretKeyMaterials[bobConnectionID].keyID)

	assert.Equal(t, bob.secretKeyMaterial, r2.remoteSecretKeyMaterials[bobConnectionID].secretKeyMaterial)
	assert.Equal(t, bob.secretKeyMaterial, alice.sessions[bobConnectionID].remoteSecretKeyMaterial)

	assert.Equal(t, uint32(1), alice.keyID)
	assert.Equal(t, uint32(0), alice.sessions[bobConnectionID].remoteKeyID)

	// Carol を登場させる
	carolConnectionID := "CAROL---------------------"

	carol, _ := initE2EE()
	carol.init()
	carol.start(carolConnectionID)

	err = carol.addPreKeyBundle(aliceConnectionID, alice.selfPreKeyBundle)
	assert.Nil(t, err)
	err = carol.addPreKeyBundle(bobConnectionID, bob.selfPreKeyBundle)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(carol.remoteFingerprints()))

	r3, err := alice.startSession(carolConnectionID, carol.selfPreKeyBundle)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(alice.remoteFingerprints()))
	assert.Equal(t, 2, len(r3.messages))
	assert.Equal(t, aliceConnectionID, r3.selfConnectionID)
	// carol がきたので key を ratchet したので 2 へ
	assert.Equal(t, uint32(2), alice.keyID)

	r4, err := carol.receiveMessage(r3.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r4.messages))
	// carol は新規参加者なので key は 0 のまま
	assert.Equal(t, uint32(0), carol.keyID)

	r5, err := carol.receiveMessage(r3.messages[1])
	assert.Nil(t, err)
	assert.Equal(t, 1, len(r5.messages))
	// carol は新規参加者なので key は 0 のまま
	assert.Equal(t, uint32(0), carol.keyID)

	r6, err := bob.startSession(carolConnectionID, carol.selfPreKeyBundle)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(bob.remoteFingerprints()))
	assert.Equal(t, bobConnectionID, r6.selfConnectionID)
	// 新規参加者がきたので鍵を ratchet した
	assert.Equal(t, uint32(1), bob.keyID)

	r7, err := carol.receiveMessage(r6.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r7.messages))
	assert.Equal(t, uint32(0), carol.keyID)

	r8, err := carol.receiveMessage(r6.messages[1])
	assert.Nil(t, err)
	assert.Equal(t, 1, len(r8.messages))
	assert.Equal(t, uint32(0), carol.keyID)

	r9, err := alice.receiveMessage(r5.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r9.messages))
	assert.Equal(t, uint32(2), alice.keyID)

	r10, err := bob.receiveMessage(r8.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r10.messages))
	assert.Equal(t, uint32(1), bob.keyID)

	assert.Equal(t, alice.secretKeyMaterial, bob.sessions[aliceConnectionID].remoteSecretKeyMaterial)
	assert.Equal(t, alice.secretKeyMaterial, carol.sessions[aliceConnectionID].remoteSecretKeyMaterial)

	assert.Equal(t, bob.secretKeyMaterial, alice.sessions[bobConnectionID].remoteSecretKeyMaterial)
	assert.Equal(t, bob.secretKeyMaterial, carol.sessions[bobConnectionID].remoteSecretKeyMaterial)

	assert.Equal(t, carol.secretKeyMaterial, alice.sessions[carolConnectionID].remoteSecretKeyMaterial)
	assert.Equal(t, carol.secretKeyMaterial, bob.sessions[carolConnectionID].remoteSecretKeyMaterial)

	r11, err := alice.stopSession(carolConnectionID)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(alice.remoteFingerprints()))
	assert.Equal(t, 1, len(r11.messages))
	assert.Equal(t, aliceConnectionID, r11.selfConnectionID)
	assert.Equal(t, uint32(3), alice.keyID)
	assert.Equal(t, uint32(3), r11.selfKeyID)

	r12, err := bob.stopSession(carolConnectionID)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(bob.remoteFingerprints()))
	assert.Equal(t, 1, len(r12.messages))
	assert.Equal(t, bobConnectionID, r12.selfConnectionID)
	assert.Equal(t, uint32(2), bob.keyID)
	assert.Equal(t, uint32(2), r12.selfKeyID)

	r13, err := alice.receiveMessage(r12.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r13.messages))

	r14, err := bob.receiveMessage(r11.messages[0])
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r14.messages))

	assert.Equal(t, uint32(2), alice.sessions[bobConnectionID].remoteKeyID)
	assert.Equal(t, uint32(3), bob.sessions[aliceConnectionID].remoteKeyID)

	assert.Equal(t, alice.secretKeyMaterial, bob.sessions[aliceConnectionID].remoteSecretKeyMaterial)
	assert.Equal(t, bob.secretKeyMaterial, alice.sessions[bobConnectionID].remoteSecretKeyMaterial)

}
