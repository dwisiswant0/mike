// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package mike_test

import (
	"testing"

	"go.dw1.io/mike" //nolint:depguard // The package under test; the default rule allows only the standard library.
)

func BenchmarkGenerateKey(b *testing.B) {
	for _, params := range parameterSets() {
		b.Run(params.String(), func(b *testing.B) {
			for b.Loop() {
				_, err := params.GenerateKey()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSharedSecret(b *testing.B) {
	for _, params := range parameterSets() {
		b.Run(params.String(), func(b *testing.B) {
			alice, err := params.GenerateKey()
			if err != nil {
				b.Fatal(err)
			}

			bob, err := params.GenerateKey()
			if err != nil {
				b.Fatal(err)
			}

			for b.Loop() {
				_, err := alice.SharedSecret(bob.PublicKey())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkNewPublicKey(b *testing.B) {
	key, err := mike.Fast1().GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	encoded := key.PublicKey().Bytes()

	for b.Loop() {
		_, err := mike.Fast1().NewPublicKey(encoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}
