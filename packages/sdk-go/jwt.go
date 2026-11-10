package auth4

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type tokenKind int

const (
	accessKind tokenKind = iota
	idKind
)

// jwtParts is a compact JWS split into its decoded parts. Nothing in it is trusted until the
// signature has been verified.
type jwtParts struct {
	header       map[string]json.RawMessage
	payload      []byte
	signingInput []byte
	signature    []byte
}

func parseJWT(token string) (*jwtParts, error) {
	if len(token) == 0 || len(token) > maxTokenLength {
		return nil, errors.New("token is empty or too long")
	}
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, errors.New("token is not a compact JWS")
	}
	decode := base64.RawURLEncoding.Strict().DecodeString
	headerBytes, err := decode(segments[0])
	if err != nil {
		return nil, err
	}
	payload, err := decode(segments[1])
	if err != nil {
		return nil, err
	}
	signature, err := decode(segments[2])
	if err != nil {
		return nil, err
	}
	header, err := decodeObject(headerBytes)
	if err != nil {
		return nil, err
	}
	return &jwtParts{
		header:       header,
		payload:      payload,
		signingInput: []byte(segments[0] + "." + segments[1]),
		signature:    signature,
	}, nil
}

// checkHeader enforces RS256, a bounded kid, the typ that separates the two token kinds (as
// packages/crypto signs them) and no key-location or critical headers. It returns the kid.
func (j *jwtParts) checkHeader(kind tokenKind) (string, bool) {
	text := func(name string) string {
		value, ok := j.header[name]
		if !ok {
			return ""
		}
		parsed, _ := jsonString(value)
		return parsed
	}
	typ := strings.ToLower(text("typ"))
	typeMatches := typ == "jwt"
	if kind == accessKind {
		typeMatches = typ == "at+jwt" || typ == "application/at+jwt"
	}
	kid := text("kid")
	if text("alg") != "RS256" || !typeMatches || len(kid) < 1 || len(kid) > 128 {
		return "", false
	}
	for _, forbidden := range []string{"jku", "x5u", "jwk", "crit"} {
		if _, present := j.header[forbidden]; present {
			return "", false
		}
	}
	return kid, true
}

func (j *jwtParts) verify(key *rsa.PublicKey) bool {
	digest := sha256.Sum256(j.signingInput)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], j.signature) == nil
}
