// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package mike_test

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"math/big"
	"slices"
	"sync"
	"testing"
	"testing/cryptotest"

	"go.dw1.io/mike" //nolint:depguard // The package under test; the default rule allows only the standard library.
)

func parameterSets() []mike.ParameterSet {
	return []mike.ParameterSet{
		mike.Fast1(), mike.Fast3(), mike.Fast5(),
		mike.Rigorous1(), mike.Rigorous3(), mike.Rigorous5(),
	}
}

// skipInShortMode skips the test in short mode, except for Fast1, the fastest
// parameter set.
func skipInShortMode(t *testing.T, params mike.ParameterSet) {
	t.Helper()

	if testing.Short() && params != mike.Fast1() {
		t.Skip("skipping in short mode")
	}
}

func mustGenerate(t *testing.T, params mike.ParameterSet) *mike.PrivateKey {
	t.Helper()

	key, err := params.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func TestSharedSecretAgreement(t *testing.T) {
	t.Parallel()

	for _, params := range parameterSets() {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			skipInShortMode(t, params)

			for range 3 {
				checkAgreement(t, params)
			}
		})
	}
}

// checkAgreement checks that two fresh key pairs derive the same shared
// secret.
func checkAgreement(t *testing.T, params mike.ParameterSet) {
	t.Helper()

	alice := mustGenerate(t, params)
	bob := mustGenerate(t, params)

	if alice.Equal(bob) || alice.PublicKey().Equal(bob.PublicKey()) {
		t.Fatal("generated identical keys")
	}

	aliceSecret, err := alice.SharedSecret(bob.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	bobSecret, err := bob.SharedSecret(alice.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatalf("shared secrets differ: %x and %x", aliceSecret, bobSecret)
	}

	if len(aliceSecret) != mike.SharedSecretSize {
		t.Fatalf("shared secret has %d bytes, want %d", len(aliceSecret), mike.SharedSecretSize)
	}
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()

	params := mike.Fast1()
	alice := mustGenerate(t, params)
	bob := mustGenerate(t, params)

	want, err := alice.SharedSecret(bob.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			_, err := params.GenerateKey()
			if err != nil {
				t.Error(err)
			}

			got, err := alice.SharedSecret(bob.PublicKey())
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("SharedSecret = %x, %v; want %x", got, err, want)
			}
		})
	}

	workers.Wait()
}

func TestKeyRoundTrip(t *testing.T) {
	t.Parallel()

	for _, params := range parameterSets() {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			skipInShortMode(t, params)
			checkRoundTrip(t, params)
		})
	}
}

// checkRoundTrip checks that a key pair survives encoding and decoding.
func checkRoundTrip(t *testing.T, params mike.ParameterSet) {
	t.Helper()

	key := mustGenerate(t, params)

	decoded, err := params.NewPrivateKey(key.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !key.Equal(decoded) || !key.PublicKey().Equal(decoded.PublicKey()) {
		t.Error("private key does not round-trip")
	}

	checkPublicKeyRoundTrip(t, key)
}

// checkPublicKeyRoundTrip checks that the public key of key survives encoding
// and decoding.
func checkPublicKeyRoundTrip(t *testing.T, key *mike.PrivateKey) {
	t.Helper()

	params := key.ParameterSet()

	pub, err := params.NewPublicKey(key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !pub.Equal(key.PublicKey()) || !bytes.Equal(pub.Bytes(), key.PublicKey().Bytes()) {
		t.Error("public key does not round-trip")
	}

	if pub.ParameterSet() != params {
		t.Error("wrong parameter set")
	}

	if public, ok := key.Public().(*mike.PublicKey); !ok || public != key.PublicKey() {
		t.Error("Public and PublicKey disagree")
	}
}

func TestBytesReturnsCopy(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, mike.Fast1())

	priv := key.Bytes()
	priv[1] ^= 1

	if bytes.Equal(priv, key.Bytes()) {
		t.Error("PrivateKey.Bytes aliases the key")
	}

	pub := key.PublicKey().Bytes()
	pub[0] ^= 1

	if bytes.Equal(pub, key.PublicKey().Bytes()) {
		t.Error("PublicKey.Bytes aliases the key")
	}
}

//nolint:paralleltest // SetGlobalRandom panics in parallel tests.
func TestGenerateKeyDeterministic(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 1)
	first := mustGenerate(t, mike.Fast1())

	cryptotest.SetGlobalRandom(t, 1)
	second := mustGenerate(t, mike.Fast1())

	if !first.Equal(second) {
		t.Error("GenerateKey does not use crypto/rand")
	}
}

func TestEqualTypes(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, mike.Fast1())

	x25519, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if key.Equal(x25519) || key.PublicKey().Equal(x25519.PublicKey()) {
		t.Error("keys compare equal to ECDH keys")
	}

	// The same bytes under a different parameter set are a different key.
	other := mike.NewPublicKeyUnchecked(mike.Rigorous1(), key.PublicKey().Bytes())
	if key.PublicKey().Equal(other) {
		t.Error("keys from different parameter sets compare equal")
	}
}

func TestParameterMismatch(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	fast := mustGenerate(t, mike.Fast1())
	rigorous := mustGenerate(t, mike.Rigorous1())

	_, err := fast.SharedSecret(rigorous.PublicKey())
	if !errors.Is(err, mike.ErrParameterMismatch) {
		t.Errorf("got %v, want %v", err, mike.ErrParameterMismatch)
	}
}

func TestInvalidParameterSet(t *testing.T) {
	t.Parallel()

	var params mike.ParameterSet

	if got := params.String(); got != "ParameterSet(0)" {
		t.Errorf("String() = %q", got)
	}

	_, err := params.GenerateKey()
	if !errors.Is(err, mike.ErrInvalidParameterSet) {
		t.Errorf("GenerateKey: got %v, want %v", err, mike.ErrInvalidParameterSet)
	}

	_, err = params.NewPrivateKey(make([]byte, 29))
	if !errors.Is(err, mike.ErrInvalidParameterSet) {
		t.Errorf("NewPrivateKey: got %v, want %v", err, mike.ErrInvalidParameterSet)
	}

	_, err = params.NewPublicKey(make([]byte, 80))
	if !errors.Is(err, mike.ErrInvalidParameterSet) {
		t.Errorf("NewPublicKey: got %v, want %v", err, mike.ErrInvalidParameterSet)
	}

	var zero mike.PrivateKey

	_, err = zero.SharedSecret(new(mike.PublicKey))
	if !errors.Is(err, mike.ErrInvalidParameterSet) {
		t.Errorf("SharedSecret: got %v, want %v", err, mike.ErrInvalidParameterSet)
	}
}

func TestNewPrivateKeyInvalid(t *testing.T) {
	t.Parallel()

	for _, params := range parameterSets() {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			skipInShortMode(t, params)

			for name, key := range invalidPrivateKeys(mustGenerate(t, params).Bytes()) {
				got, err := params.NewPrivateKey(key)
				if got != nil || !errors.Is(err, mike.ErrInvalidPrivateKey) {
					t.Errorf("%s: got %v, %v; want %v", name, got, err, mike.ErrInvalidPrivateKey)
				}
			}
		})
	}
}

// invalidPrivateKeys returns modifications of the valid key that are not
// valid private keys, by description.
func invalidPrivateKeys(valid []byte) map[string][]byte {
	modify := func(change func([]byte)) []byte {
		key := bytes.Clone(valid)
		change(key)

		return key
	}

	return map[string][]byte{
		"empty":     nil,
		"short":     valid[:len(valid)-1],
		"long":      append(bytes.Clone(valid), 0),
		"even":      modify(func(key []byte) { key[0] &^= 1 }),
		"1 mod 8":   modify(func(key []byte) { key[0] = key[0]&^7 | 1 }),
		"7 mod 8":   modify(func(key []byte) { key[0] |= 7 }),
		"too large": modify(func(key []byte) { key[len(key)-1] |= 0x80 }),
	}
}

// fast1Prime returns the prime of Fast1.
func fast1Prime() *big.Int {
	prime := new(big.Int).Lsh(big.NewInt(633), 308)

	return prime.Sub(prime, big.NewInt(1))
}

// fast1PublicKey returns the Fast1 public key encoding of realPart + i·imagPart.
func fast1PublicKey(realPart, imagPart *big.Int) []byte {
	encode := func(v *big.Int) []byte {
		encoded := v.FillBytes(make([]byte, 40))
		slices.Reverse(encoded)

		return encoded
	}

	return append(encode(realPart), encode(imagPart)...)
}

// The tests in the per-prime packages check which error each invalid public
// key causes; these tests check that the errors reach the caller.

func TestNewPublicKeyInvalid(t *testing.T) {
	t.Parallel()

	for name, key := range map[string][]byte{
		"short":         make([]byte, 79),
		"non-canonical": fast1PublicKey(fast1Prime(), big.NewInt(1)),
		"in GF(p)":      fast1PublicKey(big.NewInt(1), big.NewInt(0)),
	} {
		got, err := mike.Fast1().NewPublicKey(key)
		if got != nil || err == nil {
			t.Errorf("%s: got %v, %v; want an error", name, got, err)
		}
	}
}

func TestSharedSecretInvalidPublicKey(t *testing.T) {
	t.Parallel()

	params := mike.Fast1()
	key := mustGenerate(t, params)

	// y² = x³ + i·x² + x is an ordinary curve for this prime.
	ordinary, err := params.NewPublicKey(fast1PublicKey(big.NewInt(0), big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}

	secret, err := key.SharedSecret(ordinary)
	if secret != nil || err == nil {
		t.Errorf("ordinary curve: got %x, %v; want an error", secret, err)
	}

	// −A defines an isomorphic curve, but not the normalized one.
	negated, err := params.NewPublicKey(negate(mustGenerate(t, params).PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	secret, err = key.SharedSecret(negated)
	if secret != nil || err == nil {
		t.Errorf("non-normalized curve: got %x, %v; want an error", secret, err)
	}
}

// negate returns the encoding of −A for the Fast1 public key encoding of A.
func negate(encoded []byte) []byte {
	prime := fast1Prime()
	parts := [][]byte{slices.Clone(encoded[:40]), slices.Clone(encoded[40:])}

	for index, part := range parts {
		slices.Reverse(part)

		value := new(big.Int).SetBytes(part)
		value.Sub(prime, value).Mod(value, prime)

		parts[index] = value.Bytes()
	}

	return fast1PublicKey(new(big.Int).SetBytes(parts[0]), new(big.Int).SetBytes(parts[1]))
}

func TestParameterSetString(t *testing.T) {
	t.Parallel()

	want := []string{"FastMIKE-I", "FastMIKE-III", "FastMIKE-V", "RigorousMIKE-I", "RigorousMIKE-III", "RigorousMIKE-V"}
	for index, params := range parameterSets() {
		if got := params.String(); got != want[index] {
			t.Errorf("String() = %q, want %q", got, want[index])
		}
	}
}

func TestKeySizes(t *testing.T) {
	t.Parallel()

	// The sizes documented in the package comment.
	for _, test := range []struct {
		params                        mike.ParameterSet
		publicKeySize, privateKeySize int
	}{
		{mike.Fast1(), 80, 29},
		{mike.Fast3(), 122, 43},
		{mike.Fast5(), 160, 57},
		{mike.Rigorous1(), 96, 47},
		{mike.Rigorous3(), 144, 71},
		{mike.Rigorous5(), 192, 95},
	} {
		t.Run(test.params.String(), func(t *testing.T) {
			t.Parallel()
			skipInShortMode(t, test.params)

			key := mustGenerate(t, test.params)
			pub, priv := len(key.PublicKey().Bytes()), len(key.Bytes())

			if pub != test.publicKeySize || priv != test.privateKeySize {
				t.Errorf("sizes %d and %d, want %d and %d", pub, priv, test.publicKeySize, test.privateKeySize)
			}

			if pub > mike.MaxPublicKeySize || priv > mike.MaxPrivateKeySize {
				t.Error("key sizes exceed MaxPublicKeySize or MaxPrivateKeySize")
			}
		})
	}
}
