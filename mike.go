// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

// Package mike implements MIKE (Module Isogeny Key Exchange), a fast and
// compact post-quantum non-interactive key exchange based on isogenies.
//
// Two parties that know each other's public keys derive the same shared
// secret without exchanging any further messages, as in Diffie-Hellman.
//
// The package provides the six parameter sets from the paper. The FastMIKE
// sets have smaller keys and run faster. The RigorousMIKE sets use more
// conservative parameters, and their security proof needs one assumption
// fewer: for FastMIKE, the paper also assumes that public keys are
// indistinguishable from random supersingular curves. Sizes in bytes:
//
//	Parameter set   NIST level   Public key   Private key
//	Fast1           I                    80            29
//	Fast3           III                 122            43
//	Fast5           V                   160            57
//	Rigorous1       I                    96            47
//	Rigorous3       III                 144            71
//	Rigorous5       V                   192            95
//
// Keys and shared secrets match the Rust reference implementation, including
// its known-answer tests. MIKE is new, and its parameters might change as
// cryptanalysis progresses.
package mike

//go:generate go run ./internal/gen
//go:generate go run -C internal/asmgen .

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
)

// ParameterSet identifies a MIKE parameter set: a prime field, a starting
// curve with a torsion basis, and the degree 2^e of the secret isogeny.
//
// The valid parameter sets are returned by [Fast1], [Fast3], [Fast5],
// [Rigorous1], [Rigorous3], and [Rigorous5]. Other values, including the
// zero value, are invalid, and methods return errors for them. Parameter
// sets can be compared with == and are safe for concurrent use.
type ParameterSet uint8

// SharedSecretSize is the size in bytes of the output of
// [PrivateKey.SharedSecret].
const SharedSecretSize = 32

// The largest key sizes, those of Rigorous5.
const (
	maxPublicKeySize  = 192
	maxPrivateKeySize = 95
)

var (
	errInvalidParameterSet = errors.New("mike: invalid parameter set")
	errInvalidPrivateKey   = errors.New("mike: invalid private key")
	errParameterMismatch   = errors.New("mike: private key and public key parameter sets do not match")
)

// String returns the name of the parameter set, such as "FastMIKE-I".
func (ps ParameterSet) String() string {
	impl, ok := ps.impl()
	if !ok {
		return "ParameterSet(" + strconv.Itoa(int(ps)) + ")"
	}

	return impl.name
}

// GenerateKey generates a random PrivateKey using [crypto/rand.Read].
//
// Like [crypto/mlkem.GenerateKey768], it takes no io.Reader. For
// deterministic tests, use [testing/cryptotest.SetGlobalRandom].
func (ps ParameterSet) GenerateKey() (*PrivateKey, error) {
	impl, ok := ps.impl()
	if !ok {
		return nil, errInvalidParameterSet
	}

	key := make([]byte, impl.privateKeySize)
	rand.Read(key)
	impl.clampPrivateKey(key)

	return ps.NewPrivateKey(key)
}

// NewPrivateKey checks that key is a valid private key encoding and returns
// a PrivateKey. It computes the public key, which takes about as long as
// GenerateKey.
//
// A private key is a little-endian integer s with s ≡ 3 mod 8 and s < 2^e.
// NewPrivateKey rejects encodings of other values.
func (ps ParameterSet) NewPrivateKey(key []byte) (*PrivateKey, error) {
	impl, ok := ps.impl()
	if !ok {
		return nil, errInvalidParameterSet
	}

	if len(key) != impl.privateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", errInvalidPrivateKey, len(key), impl.privateKeySize)
	}

	// A key is valid exactly when clamping leaves it unchanged. Only the
	// clamped bits can differ, and those are fixed for valid keys.
	clamped := bytes.Clone(key)
	impl.clampPrivateKey(clamped)

	if subtle.ConstantTimeCompare(clamped, key) != 1 {
		return nil, fmt.Errorf("%w: the key must encode an integer s < 2^e with s ≡ 3 mod 8", errInvalidPrivateKey)
	}

	publicKey := &PublicKey{params: ps, publicKey: impl.publicKey(clamped)}

	return &PrivateKey{params: ps, privateKey: clamped, publicKey: publicKey}, nil
}

// NewPublicKey checks that key is a valid public key encoding and returns a
// PublicKey.
//
// A public key is the Montgomery coefficient A of a curve y² = x³ + Ax² + x,
// encoded as two little-endian integers in [0, p): the real part followed by
// the imaginary part. NewPublicKey rejects non-canonical encodings and curves
// defined over GF(p). [PrivateKey.SharedSecret] runs the more expensive
// checks: that the curve is supersingular and in normalized form.
func (ps ParameterSet) NewPublicKey(key []byte) (*PublicKey, error) {
	impl, ok := ps.impl()
	if !ok {
		return nil, errInvalidParameterSet
	}

	err := impl.checkPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("mike: %w", err)
	}

	return &PublicKey{params: ps, publicKey: bytes.Clone(key)}, nil
}

// PublicKey is a MIKE public key, usually a peer's key sent over the wire.
type PublicKey struct {
	params    ParameterSet
	publicKey []byte
}

// Bytes returns a copy of the encoding of the public key.
func (k *PublicKey) Bytes() []byte {
	// Copy to a fixed-size buffer that can be allocated on the caller's
	// stack after inlining.
	var buf [maxPublicKeySize]byte

	return append(buf[:0], k.publicKey...)
}

// Equal reports whether x represents the same public key as k.
//
// This check runs in constant time as long as the key types and their
// parameter sets match.
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	if !ok {
		return false
	}

	return k.params == other.params &&
		subtle.ConstantTimeCompare(k.publicKey, other.publicKey) == 1
}

// ParameterSet returns the parameter set of the key.
func (k *PublicKey) ParameterSet() ParameterSet {
	return k.params
}

// PrivateKey is a MIKE private key, usually kept secret.
type PrivateKey struct {
	params     ParameterSet
	privateKey []byte
	publicKey  *PublicKey
}

// SharedSecret computes the shared secret between k and the peer's public
// key remote. Both keys must belong to the same parameter set.
//
// The result is SHA3-256 of the MIKE invariants of the shared abelian
// fourfold, as in the reference implementations. As with Diffie-Hellman,
// protocols should derive keys from it with a KDF that also binds both
// public keys and, where applicable, the identities of the parties, as in
// the MIKE NIKE construction.
//
// SharedSecret returns an error if remote is not a supersingular curve in
// normalized form. Validating the peer key this way costs little extra,
// because the checks reuse the torsion basis needed for the computation.
func (k *PrivateKey) SharedSecret(remote *PublicKey) ([]byte, error) {
	if k.params != remote.params {
		return nil, errParameterMismatch
	}

	impl, ok := k.params.impl()
	if !ok {
		return nil, errInvalidParameterSet
	}

	secret, err := impl.sharedSecret(k.privateKey, remote.publicKey)
	if err != nil {
		return nil, fmt.Errorf("mike: %w", err)
	}

	return secret, nil
}

// Bytes returns a copy of the encoding of the private key.
func (k *PrivateKey) Bytes() []byte {
	// Copy to a fixed-size buffer that can be allocated on the caller's
	// stack after inlining.
	var buf [maxPrivateKeySize]byte

	return append(buf[:0], k.privateKey...)
}

// Equal reports whether x represents the same private key as k.
//
// This check runs in constant time as long as the key types and their
// parameter sets match.
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	if !ok {
		return false
	}

	return k.params == other.params &&
		subtle.ConstantTimeCompare(k.privateKey, other.privateKey) == 1
}

// ParameterSet returns the parameter set of the key.
func (k *PrivateKey) ParameterSet() ParameterSet {
	return k.params
}

// PublicKey returns the public key corresponding to k.
func (k *PrivateKey) PublicKey() *PublicKey {
	return k.publicKey
}

// Public implements the implicit interface of all standard library private
// keys. See the docs of [crypto.PrivateKey].
func (k *PrivateKey) Public() crypto.PublicKey {
	return k.PublicKey()
}
