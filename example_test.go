// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package mike_test

import (
	"bytes"
	"fmt"
	"log"

	"go.dw1.io/mike" //nolint:depguard // The package under test; the default rule allows only the standard library.
)

func Example() {
	// Alice and Bob each generate a key pair and publish the public key.
	alice, err := mike.Fast1().GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	bob, err := mike.Fast1().GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// Each side parses the peer's public key from its encoding.
	bobPub, err := mike.Fast1().NewPublicKey(bob.PublicKey().Bytes())
	if err != nil {
		log.Fatal(err)
	}

	alicePub, err := mike.Fast1().NewPublicKey(alice.PublicKey().Bytes())
	if err != nil {
		log.Fatal(err)
	}

	// Both compute the same shared secret without further interaction.
	aliceSecret, err := alice.SharedSecret(bobPub)
	if err != nil {
		log.Fatal(err)
	}

	bobSecret, err := bob.SharedSecret(alicePub)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(bytes.Equal(aliceSecret, bobSecret), len(aliceSecret))
	// Output: true 32
}
