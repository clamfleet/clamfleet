// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// target.go: target configuration types and validation: the sealed webhook
// secret, the signing key format, webhook URL validation and the display form
// of a URL.
//
// A webhook URL is a credential for many receivers (chat tools carry their token
// in the path), so no error produced here ever contains the URL, and the
// display form keeps scheme, host and port only.
package alert

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// WebhookSecret is the sealed secret of a webhook target (purpose alert-target,
// AAD = target id): the URL and the signing key.
type WebhookSecret struct {
	URL string `json:"url"`
	// SigningKey is the Standard Webhooks key as shown to the admin: whsec_ plus
	// the base64 of the HMAC key bytes.
	SigningKey string `json:"signing_key"`
}

// WebhookConfig is the non-secret config JSON of a webhook target.
type WebhookConfig struct {
	// URLDisplay is scheme://host[:port]/... : enough to recognise the target.
	URLDisplay string `json:"url_display"`
	// Plaintext marks an http:// target (the console shows "unencrypted").
	Plaintext bool `json:"plaintext"`
}

// signingKeyPrefix is the Standard Webhooks serialisation prefix.
const signingKeyPrefix = "whsec_"

// signingKeyBytes is the length of a generated key; the spec allows 24 to 64.
const signingKeyBytes = 32

// NewSigningKey returns a fresh key in its whsec_ form.
func NewSigningKey() (string, error) {
	b := make([]byte, signingKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return signingKeyPrefix + base64.StdEncoding.EncodeToString(b), nil
}

// DecodeSigningKey returns the HMAC key: the base64-DECODED bytes after
// "whsec_", not the whsec_ string. Signing with the string instead would not
// verify in any Standard Webhooks library.
func DecodeSigningKey(s string) ([]byte, error) {
	if !strings.HasPrefix(s, signingKeyPrefix) {
		return nil, errors.New("signing key has no whsec_ prefix")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, signingKeyPrefix))
	if err != nil || len(b) == 0 {
		return nil, errors.New("signing key is not valid base64")
	}
	return b, nil
}

// Marshal encodes the secret as the plaintext to seal.
func (w WebhookSecret) Marshal() ([]byte, error) { return json.Marshal(w) }

// ParseWebhookSecret decodes an opened secret.
func ParseWebhookSecret(b []byte) (WebhookSecret, error) {
	var w WebhookSecret
	if err := json.Unmarshal(b, &w); err != nil || w.URL == "" || w.SigningKey == "" {
		return WebhookSecret{}, errors.New("stored webhook secret is not readable")
	}
	return w, nil
}

// MaxURLBytes bounds a webhook URL.
const MaxURLBytes = 2048

// ValidatedURL is a webhook URL that passed ValidateWebhookURL.
type ValidatedURL struct {
	URL *url.URL
	// Display is scheme://host[:port]/... for the target list.
	Display string
	// Plaintext is true for http://.
	Plaintext bool
}

// ValidateWebhookURL checks a URL at save time (create, and every change of the
// URL): absolute http or https, a host, no userinfo, no fragment, at most 2048
// bytes, the localhost names only with AllowLoopback, an IP literal against the
// policy, and no http to a public IP literal (decision 19). Names are resolved
// at connection time, not here: DNS may change.
//
// Errors name the reason and NEVER the URL.
func ValidateWebhookURL(raw string, p Policy) (ValidatedURL, error) {
	if len(raw) > MaxURLBytes {
		return ValidatedURL{}, errors.New("URL is longer than 2048 bytes")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return ValidatedURL{}, errors.New("URL contains spaces or control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ValidatedURL{}, errors.New("not a valid URL") // url.Parse echoes its input: say nothing of it
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ValidatedURL{}, errors.New("URL must start with http:// or https://")
	}
	host := u.Hostname()
	if host == "" {
		return ValidatedURL{}, errors.New("URL has no host")
	}
	if u.User != nil {
		return ValidatedURL{}, errors.New("URL must not contain a user name or password (credentials in URLs end up in logs)")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return ValidatedURL{}, errors.New("URL must not contain a fragment")
	}
	if isLocalhostName(host) && !p.AllowLoopback {
		return ValidatedURL{}, &PermanentError{Code: "blocked", Msg: "host name " + host + " is loopback; set alert.webhook.allow_loopback to allow it"}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := p.CheckAddr(ip); err != nil {
			return ValidatedURL{}, err
		}
		if u.Scheme == "http" {
			if err := CheckPlaintext(ip); err != nil {
				return ValidatedURL{}, err
			}
		}
	}
	return ValidatedURL{URL: u, Display: DisplayURL(u), Plaintext: u.Scheme == "http"}, nil
}

// DisplayURL is scheme://host[:port]/... : never the path, query or userinfo.
func DisplayURL(u *url.URL) string { return u.Scheme + "://" + u.Host + "/…" }
