// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package mike

import (
	// The packages internal/p308, internal/p374, and so on implement the
	// computations for each prime. They are generated from internal/p308.
	"go.dw1.io/mike/internal/p308" //nolint:depguard // The module's own packages; the default rule allows only the standard library.
	"go.dw1.io/mike/internal/p374" //nolint:depguard // See above.
	"go.dw1.io/mike/internal/p474" //nolint:depguard // See above.
	"go.dw1.io/mike/internal/p566" //nolint:depguard // See above.
	"go.dw1.io/mike/internal/p628" //nolint:depguard // See above.
	"go.dw1.io/mike/internal/p758" //nolint:depguard // See above.
)

// The valid parameter sets. The zero value is invalid.
const (
	fast1 ParameterSet = iota + 1
	fast3
	fast5
	rigorous1
	rigorous3
	rigorous5
)

// Fast1 returns the FastMIKE parameter set for NIST security level I. It
// uses the prime p = 633·2^308 − 1 and e = 228.
func Fast1() ParameterSet { return fast1 }

// Fast3 returns the FastMIKE parameter set for NIST security level III. It
// uses the prime p = 593·2^474 − 1 and e = 340.
func Fast3() ParameterSet { return fast3 }

// Fast5 returns the FastMIKE parameter set for NIST security level V. It
// uses the prime p = 317·2^628 − 1 and e = 452.
func Fast5() ParameterSet { return fast5 }

// Rigorous1 returns the RigorousMIKE parameter set for NIST security level
// I. It uses the prime p = 117·2^374 − 1 and e = 372.
func Rigorous1() ParameterSet { return rigorous1 }

// Rigorous3 returns the RigorousMIKE parameter set for NIST security level
// III. It uses the prime p = 77·2^566 − 1 and e = 564.
func Rigorous3() ParameterSet { return rigorous3 }

// Rigorous5 returns the RigorousMIKE parameter set for NIST security level
// V. It uses the prime p = 41·2^758 − 1 and e = 756.
func Rigorous5() ParameterSet { return rigorous5 }

// implementation holds the name and the computations of a parameter set.
type implementation struct {
	name            string
	privateKeySize  int
	clampPrivateKey func(key []byte)
	publicKey       func(sk []byte) []byte
	checkPublicKey  func(pk []byte) error
	sharedSecret    func(sk, pk []byte) ([]byte, error)
}

// impl returns the implementation of ps. It returns false if ps is not a
// valid parameter set.
func (ps ParameterSet) impl() (implementation, bool) {
	switch ps {
	case fast1:
		return implementation{
			"FastMIKE-I", p308.PrivateKeySize, p308.ClampPrivateKey,
			p308.PublicKey, p308.CheckPublicKey, p308.SharedSecret,
		}, true
	case fast3:
		return implementation{
			"FastMIKE-III", p474.PrivateKeySize, p474.ClampPrivateKey,
			p474.PublicKey, p474.CheckPublicKey, p474.SharedSecret,
		}, true
	case fast5:
		return implementation{
			"FastMIKE-V", p628.PrivateKeySize, p628.ClampPrivateKey,
			p628.PublicKey, p628.CheckPublicKey, p628.SharedSecret,
		}, true
	case rigorous1:
		return implementation{
			"RigorousMIKE-I", p374.PrivateKeySize, p374.ClampPrivateKey,
			p374.PublicKey, p374.CheckPublicKey, p374.SharedSecret,
		}, true
	case rigorous3:
		return implementation{
			"RigorousMIKE-III", p566.PrivateKeySize, p566.ClampPrivateKey,
			p566.PublicKey, p566.CheckPublicKey, p566.SharedSecret,
		}, true
	case rigorous5:
		return implementation{
			"RigorousMIKE-V", p758.PrivateKeySize, p758.ClampPrivateKey,
			p758.PublicKey, p758.CheckPublicKey, p758.SharedSecret,
		}, true
	default:
		var invalid implementation

		return invalid, false
	}
}
