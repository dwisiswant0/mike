// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package mike

// The identifiers below export internals to the tests in package mike_test.

var (
	ErrInvalidParameterSet = errInvalidParameterSet
	ErrInvalidPrivateKey   = errInvalidPrivateKey
	ErrParameterMismatch   = errParameterMismatch
)

const (
	MaxPublicKeySize  = maxPublicKeySize
	MaxPrivateKeySize = maxPrivateKeySize
)

// NewPublicKeyUnchecked returns a public key with the encoding key, without
// validating it.
func NewPublicKeyUnchecked(params ParameterSet, key []byte) *PublicKey {
	return &PublicKey{params: params, publicKey: key}
}
