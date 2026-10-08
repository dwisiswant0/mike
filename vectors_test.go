// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package mike_test

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"go.dw1.io/mike" //nolint:depguard // The package under test; the default rule allows only the standard library.
)

// The vectors in testdata/vectors.txt come from the Rust reference
// implementation. They cover both ways of sampling the torsion basis,
// depending on whether A is a square, for every parameter set.

// keyVector is a private key and the public key derived from it.
type keyVector struct {
	privateKey []byte
	publicKey  []byte
}

// secretVector is the shared secret of the keys with indices first and
// second.
type secretVector struct {
	first, second string
	secret        []byte
}

// vectorSet holds the vectors of one parameter set. Keys are indexed by the
// seed of the DRBG that derived them.
type vectorSet struct {
	keys    map[string]keyVector
	secrets []secretVector
}

// readVectors returns the vectors in testdata/vectors.txt, by parameter set
// name.
func readVectors(t *testing.T) map[string]*vectorSet {
	t.Helper()

	data, err := os.ReadFile("testdata/vectors.txt")
	if err != nil {
		t.Fatal(err)
	}

	sets := make(map[string]*vectorSet)

	for line := range strings.Lines(string(data)) {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}

		set := sets[fields[0]]
		if set == nil {
			set = &vectorSet{keys: make(map[string]keyVector), secrets: nil}
			sets[fields[0]] = set
		}

		set.add(t, fields)
	}

	return sets
}

// add adds the vector on a line of testdata/vectors.txt, split into fields.
func (set *vectorSet) add(t *testing.T, fields []string) {
	t.Helper()

	switch {
	case len(fields) == 5 && fields[1] == "key":
		set.keys[fields[2]] = keyVector{mustHex(t, fields[3]), mustHex(t, fields[4])}
	case len(fields) == 5 && fields[1] == "secret":
		set.secrets = append(set.secrets, secretVector{fields[2], fields[3], mustHex(t, fields[4])})
	default:
		t.Fatalf("malformed line %q", strings.Join(fields, " "))
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func TestReferenceVectors(t *testing.T) {
	t.Parallel()

	vectors := readVectors(t)

	for _, params := range parameterSets() {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			skipInShortMode(t, params)

			set := vectors[params.String()]
			if set == nil {
				t.Fatal("no vectors")
			}

			keys := checkKeyVectors(t, params, set.keys)
			checkSecretVectors(t, keys, set.secrets)
		})
	}
}

// checkKeyVectors checks that each private key yields its public key, and
// returns the keys by index.
func checkKeyVectors(t *testing.T, params mike.ParameterSet, vectors map[string]keyVector) map[string]*mike.PrivateKey {
	t.Helper()

	keys := make(map[string]*mike.PrivateKey, len(vectors))

	for index, vector := range vectors {
		key, err := params.NewPrivateKey(vector.privateKey)
		if err != nil {
			t.Fatalf("key %s: %v", index, err)
		}

		if got := key.PublicKey().Bytes(); !bytes.Equal(got, vector.publicKey) {
			t.Errorf("key %s: public key %x, want %x", index, got, vector.publicKey)
		}

		keys[index] = key
	}

	return keys
}

// checkSecretVectors checks that both parties of each vector compute its
// shared secret.
func checkSecretVectors(t *testing.T, keys map[string]*mike.PrivateKey, vectors []secretVector) {
	t.Helper()

	for _, vector := range vectors {
		first, second := keys[vector.first], keys[vector.second]
		if first == nil || second == nil {
			t.Fatalf("secret %s %s: missing keys", vector.first, vector.second)
		}

		for _, pair := range [][2]*mike.PrivateKey{{first, second}, {second, first}} {
			secret, err := pair[0].SharedSecret(pair[1].PublicKey())
			if err != nil {
				t.Fatalf("secret %s %s: %v", vector.first, vector.second, err)
			}

			if !bytes.Equal(secret, vector.secret) {
				t.Errorf("secret %s %s = %x, want %x", vector.first, vector.second, secret, vector.secret)
			}
		}
	}
}

// TestGenerateKeyMatchesReference checks that GenerateKey turns random bytes
// into a private key as the reference implementation does, by feeding it the
// DRBG output that derived the vectors.
//
//nolint:paralleltest // The test replaces the process-wide crypto/rand.Reader.
func TestGenerateKeyMatchesReference(t *testing.T) {
	vectors := readVectors(t)

	//nolint:paralleltest // See above.
	for _, params := range parameterSets() {
		t.Run(params.String(), func(t *testing.T) {
			skipInShortMode(t, params)

			for _, seed := range []byte{0, 1} {
				want := vectors[params.String()].keys[strconv.Itoa(int(seed))]

				setRandReader(t, newCTRDRBG(seed))

				key, err := params.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(key.Bytes(), want.privateKey) || !bytes.Equal(key.PublicKey().Bytes(), want.publicKey) {
					t.Errorf("seed %d: got key %x, want %x", seed, key.Bytes(), want.privateKey)
				}
			}
		})
	}
}

// setRandReader replaces crypto/rand.Reader for the duration of the test.
// The test must not run in parallel.
func setRandReader(t *testing.T, r io.Reader) {
	t.Helper()

	old := rand.Reader
	rand.Reader = r

	t.Cleanup(func() { rand.Reader = old })
}

// ctrDRBG is the AES-256 CTR_DRBG without derivation function from NIST SP
// 800-90A, as used by the NIST PQC known-answer tests. The reference
// implementations seed it to generate their test vectors.
type ctrDRBG struct {
	key [32]byte
	v   [16]byte
}

// newCTRDRBG returns the DRBG seeded with 48 bytes of value seed.
func newCTRDRBG(seed byte) *ctrDRBG {
	var material [48]byte
	for i := range material {
		material[i] = seed
	}

	drbg := new(ctrDRBG)
	drbg.update(&material)

	return drbg
}

// Read returns the next len(out) bytes, as one call to the reference
// randombytes function.
func (d *ctrDRBG) Read(out []byte) (int, error) {
	var block [16]byte

	for i := 0; i < len(out); i += 16 {
		d.next(block[:])
		copy(out[i:], block[:])
	}

	d.update(nil)

	return len(out), nil
}

func (d *ctrDRBG) next(out []byte) {
	for j := len(d.v) - 1; j >= 0; j-- {
		d.v[j]++
		if d.v[j] != 0 {
			break
		}
	}

	block, err := aes.NewCipher(d.key[:])
	if err != nil {
		panic(err)
	}

	block.Encrypt(out, d.v[:])
}

func (d *ctrDRBG) update(provided *[48]byte) {
	var material [48]byte
	for i := 0; i < len(material); i += 16 {
		d.next(material[i : i+16])
	}

	if provided != nil {
		for i := range material {
			material[i] ^= provided[i]
		}
	}

	copy(d.key[:], material[:32])
	copy(d.v[:], material[32:])
}
