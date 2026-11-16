// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// oidc.go: the console side of OpenID Connect sign-in.
package web

// OIDCProvider is the OpenID Connect sign-in (*extauth.OIDCClient); nil means auth.oidc is off.
type OIDCProvider interface{}
