package auth4

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Wire rules copied from packages/contracts (AccessTokenClaimsSchema, IdTokenClaimsSchema and
// custom-claims.ts). tests/integration/auth4d-170.go-sdk.test.ts keeps them in step. Go's $ matches
// only at the end of the text, so the patterns are the contract's patterns unchanged.

const (
	managementAudience         = "urn:auth4:management"
	guestClaim                 = "auth4_guest"
	rolesClaim                 = "auth4_roles"
	metadataClaim              = "auth4_meta"
	accessTokenLifetimeSeconds = 300
	idTokenLifetimeSeconds     = 300
	maxTokenLength             = 16_384
	maxScopes                  = 32
	maxRolesPerToken           = 20
	maxMetadataKeys            = 32
	maxMetadataBytes           = 2_048
	maxMetadataStringLength    = 256
)

var (
	tenantIDPattern    = regexp.MustCompile(`^ten_[A-Za-z0-9]{16,64}$`)
	clientIDPattern    = regexp.MustCompile(`^cli_[A-Za-z0-9]{16,64}$`)
	userIDPattern      = regexp.MustCompile(`^usr_[A-Za-z0-9]{16,64}$`)
	sessionIDPattern   = regexp.MustCompile(`^ses_[A-Za-z0-9]{16,64}$`)
	tokenIDPattern     = regexp.MustCompile(`^jti_[A-Za-z0-9_-]{16,64}$`)
	scopeNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,63}$`)
	roleNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	metadataKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	idpPattern         = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)
)

// AUTH4D-324: the opt-in player name claim, Name#1234 (read leniently).
var playerNamePattern = regexp.MustCompile(`^[^#]{1,64}#[0-9]{4}$`)

var reservedClaimNames = []string{
	"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "azp", "auth_time", "nonce", "acr", "amr",
	"sid", "scope", "client_id", "tenant_id", "token_use", "email", "email_verified",
}

// The contract schemas are strict: any other claim makes the token invalid.
var accessTokenClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
	"tenant_id": true, "token_use": true, "client_id": true, "scope": true, "sid": true,
	guestClaim: true, rolesClaim: true, metadataClaim: true, "idp": true, "name": true,
}

var idTokenClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
	"tenant_id": true, "token_use": true, "auth_time": true, "nonce": true, "email": true,
	"email_verified": true, "idp": true,
}

func isReservedClaimName(name string) bool {
	for _, reserved := range reservedClaimNames {
		if name == reserved {
			return true
		}
	}
	return strings.HasPrefix(name, "auth4_")
}

func isScopeList(value string) bool {
	if len(value) < 1 || len(value) > 2_048 {
		return false
	}
	scopes := strings.Split(value, " ")
	if len(scopes) > maxScopes {
		return false
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if !scopeNamePattern.MatchString(scope) || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return true
}

// readRoles applies RolesClaimSchema: 1 to 20 unique role names.
func readRoles(raw json.RawMessage) ([]string, bool) {
	var items []json.RawMessage
	if !isJSONArray(raw) || json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	if len(items) < 1 || len(items) > maxRolesPerToken {
		return nil, false
	}
	roles := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		role, ok := jsonString(item)
		if !ok || !roleNamePattern.MatchString(role) || seen[role] {
			return nil, false
		}
		seen[role] = true
		roles = append(roles, role)
	}
	return roles, true
}

// readMetadata applies MetadataClaimSchema: a non-empty flat object of scalar values, at most 2048
// bytes of compact JSON. Numbers become float64, as in JavaScript.
func readMetadata(raw json.RawMessage) (map[string]any, bool) {
	members, err := decodeObject(raw)
	if err != nil {
		return nil, false
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil || compact.Len() > maxMetadataBytes {
		return nil, false
	}
	if len(members) < 1 || len(members) > maxMetadataKeys {
		return nil, false
	}
	metadata := make(map[string]any, len(members))
	for name, value := range members {
		if !metadataKeyPattern.MatchString(name) || isReservedClaimName(name) {
			return nil, false
		}
		var scalar any
		if json.Unmarshal(value, &scalar) != nil {
			return nil, false
		}
		switch typed := scalar.(type) {
		case string:
			// The contract's max(256) counts UTF-16 code units, as JavaScript strings do.
			if utf16Length(typed) > maxMetadataStringLength {
				return nil, false
			}
		case float64, bool, nil:
		default:
			return nil, false
		}
		metadata[name] = scalar
	}
	return metadata, true
}

func utf16Length(value string) int {
	length := 0
	for _, r := range value {
		if r >= 0x10000 {
			length += 2
		} else {
			length++
		}
	}
	return length
}

// isEmailAddress is a loose check; auth4.dev already validated the address before signing it.
func isEmailAddress(value string) bool {
	at := strings.IndexByte(value, '@')
	return len(value) <= 254 &&
		at > 0 &&
		at == strings.LastIndexByte(value, '@') &&
		at < len(value)-1 &&
		strings.IndexFunc(value, unicode.IsSpace) < 0
}

// validateIssuer mirrors @auth4/sdk-server validateIssuer: https (or http on loopback), no
// credentials, query or fragment, path exactly /t/{tenantID}, already in canonical form.
func validateIssuer(tenantID, issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || !parsed.IsAbs() {
		return "", errors.New("auth4: Issuer must be a valid absolute URL")
	}
	origin, err := canonicalOrigin(parsed)
	if err != nil {
		return "", err
	}
	canonical := origin + "/t/" + tenantID
	if parsed.Path != "/t/"+tenantID || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || issuer != canonical {
		return "", errors.New("auth4: Issuer must be the canonical issuer URL for TenantID")
	}
	return issuer, nil
}

func issuerFromOrigin(tenantID, authOrigin string) (string, error) {
	parsed, err := url.Parse(authOrigin)
	if err != nil || !parsed.IsAbs() || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("auth4: AuthOrigin must be an origin such as https://auth.auth4.dev")
	}
	origin, err := canonicalOrigin(parsed)
	if err != nil {
		return "", err
	}
	return origin + "/t/" + tenantID, nil
}

func canonicalOrigin(parsed *url.URL) (string, error) {
	host := strings.ToLower(parsed.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	secure := parsed.Scheme == "https" || (parsed.Scheme == "http" && loopback)
	if !secure || parsed.User != nil || parsed.Opaque != "" || parsed.Host == "" {
		return "", errors.New("auth4: the issuer must use https (http only on loopback) and no credentials")
	}
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return fmt.Sprintf("%s://%s:%s", parsed.Scheme, host, port), nil
	}
	return parsed.Scheme + "://" + host, nil
}

// decodeObject reads one JSON object into its raw members. Duplicate names fail, so a claim can't
// be read one way here and another way by a different JSON parser.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	members := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("invalid member name")
		}
		if _, duplicate := members[name]; duplicate {
			return nil, errors.New("duplicate member " + name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		members[name] = value
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, errors.New("unterminated JSON object")
	}
	if _, err := decoder.Token(); err == nil {
		return nil, errors.New("trailing data after JSON object")
	}
	return members, nil
}

func jsonString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(trimmed, &value) != nil {
		return "", false
	}
	return value, true
}

func jsonBool(raw json.RawMessage) (bool, bool) {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// jsonPositiveInt accepts a JSON integer greater than zero, as z.number().int().positive() does.
func jsonPositiveInt(raw json.RawMessage) (int64, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || (trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9')) {
		return 0, false
	}
	var number json.Number
	if json.Unmarshal(trimmed, &number) != nil {
		return 0, false
	}
	value, err := number.Int64()
	if err != nil {
		// 1.8e9 and 300.0 are still integers to JavaScript.
		float, ferr := number.Float64()
		if ferr != nil || float != float64(int64(float)) || float > 1<<53 {
			return 0, false
		}
		value = int64(float)
	}
	return value, value > 0
}

func isJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}
