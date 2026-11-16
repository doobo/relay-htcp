package admin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Encrypted admin login.
//
// The browser never sends the password in the clear: it first fetches a
// one-time challenge (public keys + nonce), then encrypts
// {username, password, nonce} with either:
//
//  1. WebCrypto: a fresh AES-GCM key, itself wrapped with the server's
//     RSA-OAEP public key (preferred; needs a secure context).
//  2. TweetNaCl box: X25519 + XSalsa20-Poly1305 (fallback for plain HTTP on a
//     LAN address, where crypto.subtle is unavailable).
//
// This keeps the password out of the request body for a passive observer. It
// is not a replacement for TLS, and nonces are single-use so a captured body
// cannot be replayed.
const (
	loginNonceTTL    = 2 * time.Minute
	maxLoginNonces   = 4096
	loginChallengeOK = "RSA-OAEP-256+A256GCM"
)

// LoginCredentials is the decrypted username/password pair.
type LoginCredentials struct {
	Username string
	Password string
}

// loginJWK is the bare RSA public key imported by crypto.subtle.importKey.
type loginJWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// loginBoxKey is the TweetNaCl fallback public key.
type loginBoxKey struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

// LoginChallenge is the JSON returned by POST /api/auth/challenge.
type LoginChallenge struct {
	Algorithm string      `json:"algorithm"`
	PublicKey loginJWK    `json:"publicKey"`
	Nonce     string      `json:"nonce"`
	Box       loginBoxKey `json:"box"`
}

// challengeStore owns the process-lifetime RSA/X25519 key pairs and the table
// of outstanding single-use nonces.
type challengeStore struct {
	mu     sync.Mutex
	nonces map[string]int64

	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
	rsaErr  error

	boxOnce sync.Once
	boxPub  *[32]byte
	boxPriv *[32]byte
	boxErr  error
}

func newChallengeStore() *challengeStore {
	return &challengeStore{nonces: make(map[string]int64)}
}

// Issue returns the public keys and a fresh single-use nonce.
func (s *challengeStore) Issue() (LoginChallenge, error) {
	key, err := s.rsaKeyPair()
	if err != nil {
		return LoginChallenge{}, err
	}
	pub, err := s.boxPublicKey()
	if err != nil {
		return LoginChallenge{}, err
	}
	buf, err := randomBytes(16)
	if err != nil {
		return LoginChallenge{}, err
	}
	nonce := hex.EncodeToString(buf)

	now := time.Now().UnixMilli()
	s.mu.Lock()
	for n, expiresAt := range s.nonces {
		if expiresAt <= now {
			delete(s.nonces, n)
		}
	}
	if len(s.nonces) >= maxLoginNonces {
		s.mu.Unlock()
		return LoginChallenge{}, errors.New("too many outstanding login challenges")
	}
	s.nonces[nonce] = now + loginNonceTTL.Milliseconds()
	s.mu.Unlock()

	return LoginChallenge{
		Algorithm: loginChallengeOK,
		PublicKey: rsaPublicJWK(&key.PublicKey),
		Nonce:     nonce,
		Box: loginBoxKey{
			Algorithm: "x25519-xsalsa20-poly1305",
			PublicKey: base64.StdEncoding.EncodeToString(pub[:]),
		},
	}, nil
}

// DecryptWebCrypto unwraps the AES key with RSA-OAEP and decrypts the payload.
func (s *challengeStore) DecryptWebCrypto(keyB64, ivB64, dataB64 string) (LoginCredentials, error) {
	key, err := s.rsaKeyPair()
	if err != nil {
		return LoginCredentials{}, err
	}
	wrapped, err := decodeB64(keyB64)
	if err != nil {
		return LoginCredentials{}, err
	}
	rawKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		return LoginCredentials{}, err
	}
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return LoginCredentials{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return LoginCredentials{}, err
	}
	iv, err := decodeB64(ivB64)
	if err != nil {
		return LoginCredentials{}, err
	}
	if len(iv) != gcm.NonceSize() {
		return LoginCredentials{}, errors.New("invalid AES-GCM iv length")
	}
	ciphertext, err := decodeB64(dataB64)
	if err != nil {
		return LoginCredentials{}, err
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return LoginCredentials{}, errors.New("login payload authentication failed")
	}
	return s.parseCredentials(plaintext)
}

// DecryptBox decrypts the TweetNaCl anonymous-box fallback payload.
func (s *challengeStore) DecryptBox(publicKeyB64, nonceB64, dataB64 string) (LoginCredentials, error) {
	_, priv, err := s.boxKeyPair()
	if err != nil {
		return LoginCredentials{}, err
	}
	clientPubBytes, err := decodeB64(publicKeyB64)
	if err != nil {
		return LoginCredentials{}, err
	}
	if len(clientPubBytes) != 32 {
		return LoginCredentials{}, errors.New("invalid box public key length")
	}
	var clientPub [32]byte
	copy(clientPub[:], clientPubBytes)

	nonceBytes, err := decodeB64(nonceB64)
	if err != nil {
		return LoginCredentials{}, err
	}
	if len(nonceBytes) != 24 {
		return LoginCredentials{}, errors.New("invalid box nonce length")
	}
	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	ciphertext, err := decodeB64(dataB64)
	if err != nil {
		return LoginCredentials{}, err
	}
	opened, ok := box.Open(nil, ciphertext, &nonce, &clientPub, priv)
	if !ok {
		return LoginCredentials{}, errors.New("box decryption failed")
	}
	return s.parseCredentials(opened)
}

func (s *challengeStore) parseCredentials(raw []byte) (LoginCredentials, error) {
	var parsed struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Nonce    string `json:"nonce"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return LoginCredentials{}, errors.New("malformed login payload")
	}
	if !s.consumeNonce(parsed.Nonce) {
		return LoginCredentials{}, errors.New("unknown or expired nonce")
	}
	if parsed.Username == "" || parsed.Password == "" {
		return LoginCredentials{}, errors.New("empty credentials")
	}
	return LoginCredentials{Username: parsed.Username, Password: parsed.Password}, nil
}

// consumeNonce returns true exactly once per nonce, before it expires.
func (s *challengeStore) consumeNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce)
	return expiresAt > time.Now().UnixMilli()
}

func (s *challengeStore) rsaKeyPair() (*rsa.PrivateKey, error) {
	s.rsaOnce.Do(func() {
		s.rsaKey, s.rsaErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return s.rsaKey, s.rsaErr
}

func (s *challengeStore) boxKeyPair() (*[32]byte, *[32]byte, error) {
	s.boxOnce.Do(func() {
		pub, priv, err := box.GenerateKey(rand.Reader)
		s.boxPub, s.boxPriv, s.boxErr = pub, priv, err
	})
	return s.boxPub, s.boxPriv, s.boxErr
}

func (s *challengeStore) boxPublicKey() (*[32]byte, error) {
	pub, _, err := s.boxKeyPair()
	return pub, err
}

func rsaPublicJWK(pub *rsa.PublicKey) loginJWK {
	return loginJWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// decodeB64 accepts standard base64 with or without padding.
func decodeB64(value string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

// loginPayload is the POST /api/auth/login body. Encrypted and Box are
// mutually exclusive; Username/Password are the legacy plaintext form kept
// for scripts and curl.
type loginPayload struct {
	Encrypted *encryptedPayload `json:"encrypted,omitempty"`
	Box       *boxPayload       `json:"box,omitempty"`
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
}

type encryptedPayload struct {
	Key  string `json:"key"`
	IV   string `json:"iv"`
	Data string `json:"data"`
}

type boxPayload struct {
	PublicKey string `json:"publicKey"`
	Nonce     string `json:"nonce"`
	Data      string `json:"data"`
}

// resolveLoginCredentials decrypts whichever login shape was sent.
func (s *Server) resolveLoginCredentials(p *loginPayload) (LoginCredentials, error) {
	switch {
	case p.Encrypted != nil:
		if p.Encrypted.Key == "" || p.Encrypted.IV == "" || p.Encrypted.Data == "" {
			return LoginCredentials{}, errors.New("encrypted payload requires key, iv and data")
		}
		return s.challenges.DecryptWebCrypto(p.Encrypted.Key, p.Encrypted.IV, p.Encrypted.Data)
	case p.Box != nil:
		if p.Box.PublicKey == "" || p.Box.Nonce == "" || p.Box.Data == "" {
			return LoginCredentials{}, errors.New("box payload requires publicKey, nonce and data")
		}
		return s.challenges.DecryptBox(p.Box.PublicKey, p.Box.Nonce, p.Box.Data)
	case p.Username != "" && p.Password != "":
		return LoginCredentials{Username: p.Username, Password: p.Password}, nil
	default:
		return LoginCredentials{}, fmt.Errorf("missing credentials")
	}
}
