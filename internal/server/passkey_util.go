package server

import "encoding/base64"

// base64URL encodes a sealed ceremony blob for use in a cookie value.
// URL-safe because a cookie may not contain '+' or '/'.
func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// base64URLDecode reverses base64URL.
func base64URLDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
