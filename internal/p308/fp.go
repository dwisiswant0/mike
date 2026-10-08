// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package p308

import (
	"encoding/binary"
	"math/bits"
)

// fp is an element of the base field GF(p). It holds x·R mod p in Montgomery
// form, as little-endian 64-bit limbs, where R = 2^(64·fpLimbs). Elements are
// always fully reduced, so equal elements have equal limbs. The zero value is
// the element zero.
//
// The methods run in constant time. The receiver is the destination, it may
// alias the arguments, and it is returned for chaining. Predicates and
// conditions are 1 for true and 0 for false.
//
// The constants, the add and sub methods, and fpMulGeneric and
// fpSquareGeneric are generated in fp_arith.go for each prime. On amd64 CPUs
// that support it, mul and square run the assembly in fp_amd64.s, which
// internal/asmgen generates; otherwise, they call fpMulGeneric and
// fpSquareGeneric.
type fp struct{ l [fpLimbs]uint64 }

const (
	limbBits  = 64 // the size of a limb in bits
	limbBytes = 8  // the size of a limb in bytes

	// pow uses a fixed window of windowBits bits.
	windowBits    = 4
	windowSize    = 1 << windowBits
	windowMask    = windowSize - 1
	windowsInLimb = limbBits / windowBits
)

func (z *fp) set(x *fp) *fp {
	*z = *x

	return z
}

func (z *fp) zero() *fp {
	var zero fp

	*z = zero

	return z
}

func (z *fp) one() *fp {
	z.l = fpR

	return z
}

// setUint64 sets z = v mod p.
func (z *fp) setUint64(v uint64) *fp {
	z.l = [fpLimbs]uint64{v}

	return z.mul(z, &fp{fpR2})
}

func (z *fp) neg(x *fp) *fp {
	var zero fp

	return z.sub(&zero, x)
}

func (z *fp) double(x *fp) *fp { return z.add(x, x) }
func (z *fp) mul4(x *fp) *fp   { return z.double(x).double(z) }

// half sets z = x/2.
func (z *fp) half(elem *fp) *fp {
	// If elem is odd, elem + p is even. Because 2p < 2^(64·fpLimbs), the sum fits
	// in the limbs, and shifting it right by one bit gives elem/2 mod p.
	mask := -(elem.l[0] & 1)

	var (
		sum   [fpLimbs]uint64
		carry uint64
	)

	for i := range sum {
		sum[i], carry = bits.Add64(elem.l[i], fpP[i]&mask, carry)
	}

	for i := range len(sum) - 1 {
		z.l[i] = sum[i]>>1 | sum[i+1]<<(limbBits-1)
	}

	z.l[fpLimbs-1] = sum[fpLimbs-1] >> 1

	return z
}

// invert sets z = 1/x, or z = 0 if x = 0.
func (z *fp) invert(x *fp) *fp { return z.pow(x, &fpExpInv) }

// isSquare returns 1 if z is a square in GF(p), including zero.
func (z *fp) isSquare() uint64 {
	// By Euler's criterion, z^((p−1)/2) = 1 for nonzero squares.
	var power, one fp

	power.pow(z, &fpExpLeg)

	return power.equal(one.one()) | z.isZero()
}

func (z *fp) isZero() uint64 {
	var acc uint64
	for _, limb := range z.l {
		acc |= limb
	}

	return 1 ^ (acc|-acc)>>(limbBits-1)
}

func (z *fp) equal(y *fp) uint64 {
	var acc uint64
	for i := range z.l {
		acc |= z.l[i] ^ y.l[i]
	}

	return 1 ^ (acc|-acc)>>(limbBits-1)
}

// isOdd returns 1 if the canonical encoding of z is an odd integer.
func (z *fp) isOdd() uint64 { return fromMontgomery(z)[0] & 1 }

// selectFrom sets z = a if cond = 1 and z = b if cond = 0.
func (z *fp) selectFrom(a, b *fp, cond uint64) *fp {
	mask := -cond
	for i := range z.l {
		z.l[i] = b.l[i] ^ (mask & (a.l[i] ^ b.l[i]))
	}

	return z
}

// bytes returns the fpSize-byte little-endian encoding of z.
func (z *fp) bytes() []byte {
	var out [fpLimbs * limbBytes]byte

	for i, limb := range fromMontgomery(z) {
		binary.LittleEndian.PutUint64(out[limbBytes*i:], limb)
	}

	return out[:fpSize]
}

// setBytes sets z to the value of the little-endian encoding enc and returns
// true. If enc does not have fpSize bytes or encodes a value that is not
// below p, setBytes returns false and leaves z unchanged.
func (z *fp) setBytes(enc []byte) bool {
	if len(enc) != fpSize {
		return false
	}

	var buf [fpLimbs * limbBytes]byte

	copy(buf[:], enc)

	var value fp
	for i := range value.l {
		value.l[i] = binary.LittleEndian.Uint64(buf[limbBytes*i:])
	}

	// The value is below p exactly when subtracting p borrows.
	var borrow uint64
	for i := range value.l {
		_, borrow = bits.Sub64(value.l[i], fpP[i], borrow)
	}

	if borrow == 0 {
		return false
	}

	z.mul(&value, &fp{fpR2})

	return true
}

// pow sets z = base^exp for a public exponent exp, using a fixed window. The
// running time depends on exp but not on base.
func (z *fp) pow(base *fp, exp *[fpLimbs]uint64) *fp {
	var table [windowSize]fp

	table[0].one()
	table[1] = *base

	for i := 2; i < len(table); i++ {
		table[i].mul(&table[i-1], base)
	}

	var acc fp

	acc.one()

	started := false

	for i := len(exp)*windowsInLimb - 1; i >= 0; i-- {
		window := (exp[i/windowsInLimb] >> (windowBits * (i % windowsInLimb))) & windowMask

		if started {
			for range windowBits {
				acc.square(&acc)
			}
		}

		if window != 0 {
			acc.mul(&acc, &table[window])

			started = true
		}
	}

	*z = acc

	return z
}
