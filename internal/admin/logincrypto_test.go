package admin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

func encB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func webCryptoPayload(t *testing.T, ch LoginChallenge, username, password string) encryptedPayload {
	t.Helper()
	nBytes, err := base64.RawURLEncoding.DecodeString(ch.PublicKey.N)
	if err != nil {
		t.Fatal(err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(ch.PublicKey.E)
	if err != nil {
		t.Fatal(err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(map[string]string{
		"username": username, "password": password, "nonce": ch.Nonce,
	})
	ct := gcm.Seal(nil, iv, plain, nil)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	return encryptedPayload{Key: encB64(wrapped), IV: encB64(iv), Data: encB64(ct)}
}

func makeBoxPayload(t *testing.T, ch LoginChallenge, username, password string) boxPayload {
	t.Helper()
	srvPubRaw, err := base64.StdEncoding.DecodeString(ch.Box.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var srvPub [32]byte
	copy(srvPub[:], srvPubRaw)

	clientPub, clientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(map[string]string{
		"username": username, "password": password, "nonce": ch.Nonce,
	})
	sealed := box.Seal(nil, plain, &nonce, &srvPub, clientPriv)
	return boxPayload{
		PublicKey: encB64(clientPub[:]),
		Nonce:     encB64(nonce[:]),
		Data:      encB64(sealed),
	}
}

func TestChallengeWebCrypto(t *testing.T) {
	cs := newChallengeStore()
	ch, err := cs.Issue()
	if err != nil {
		t.Fatal(err)
	}
	p := webCryptoPayload(t, ch, "alice", "s3cret")
	creds, err := cs.DecryptWebCrypto(p.Key, p.IV, p.Data)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Username != "alice" || creds.Password != "s3cret" {
		t.Fatalf("creds = %+v", creds)
	}
	// The nonce is single-use: replaying the same body must fail.
	if _, err := cs.DecryptWebCrypto(p.Key, p.IV, p.Data); err == nil {
		t.Fatal("replayed payload accepted")
	}
}

func TestChallengeBox(t *testing.T) {
	cs := newChallengeStore()
	ch, err := cs.Issue()
	if err != nil {
		t.Fatal(err)
	}
	p := makeBoxPayload(t, ch, "bob", "hunter2")
	creds, err := cs.DecryptBox(p.PublicKey, p.Nonce, p.Data)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Username != "bob" || creds.Password != "hunter2" {
		t.Fatalf("creds = %+v", creds)
	}
	if _, err := cs.DecryptBox(p.PublicKey, p.Nonce, p.Data); err == nil {
		t.Fatal("replayed box payload accepted")
	}
}

func TestChallengeExpiredNonce(t *testing.T) {
	cs := newChallengeStore()
	ch, err := cs.Issue()
	if err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	cs.nonces[ch.Nonce] = time.Now().Add(-time.Second).UnixMilli()
	cs.mu.Unlock()
	p := webCryptoPayload(t, ch, "alice", "s3cret")
	if _, err := cs.DecryptWebCrypto(p.Key, p.IV, p.Data); err == nil {
		t.Fatal("expired nonce accepted")
	}
}

func TestChallengeEndpointAndEncryptedLogin(t *testing.T) {
	env := setupEnv(t)

	code, raw := doReq(t, env.srv, "POST", "/api/auth/challenge", "", nil)
	if code != 200 {
		t.Fatalf("challenge: %d %s", code, raw)
	}
	var ch LoginChallenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Nonce == "" || ch.PublicKey.N == "" || ch.Box.PublicKey == "" {
		t.Fatalf("challenge = %+v", ch)
	}

	p := webCryptoPayload(t, ch, "admin", "adminpass1")
	body, _ := json.Marshal(loginPayload{Encrypted: &p})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("encrypted login: %d %s", w.Code, w.Body.String())
	}
	var lr loginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &lr); err != nil {
		t.Fatal(err)
	}
	if lr.Token == "" {
		t.Fatal("no session token")
	}
}
