// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

//go:build goexperiment.simd && amd64

package p308

import (
	"math"
	"math/big"
	"math/bits"
	"simd/archsimd"
	"testing"
)

// The bounds of the vector arithmetic, as multiples of p: see vfp and
// vtheta4.hadamard.
const (
	vecMulInBound  = 48
	vecMulOutBound = 2
)

func skipWithoutAVX2(tb testing.TB) {
	tb.Helper()

	if !archsimd.X86.AVX2() {
		tb.Skip("the CPU does not support AVX2")
	}
}

// vecFromBig returns a normalized vfp whose lanes hold vals, which must be
// below R_v.
func vecFromBig(vals *[4]*big.Int) vfp {
	mask := big.NewInt(vecMask)

	var res vfp

	for limb := range res {
		var digits [4]uint64

		for lane, val := range vals {
			digit := new(big.Int).Rsh(val, uint(vecRadix*limb))
			digits[lane] = digit.And(digit, mask).Uint64()
		}

		res[limb] = archsimd.LoadUint64x4Array(&digits)
	}

	return res
}

// vecToBig returns the values of the lanes of vec. It fails if vec is not
// normalized.
func vecToBig(t *testing.T, vec *vfp) [4]*big.Int {
	t.Helper()

	var res [4]*big.Int
	for lane := range res {
		res[lane] = new(big.Int)
	}

	for limb := len(vec) - 1; limb >= 0; limb-- {
		var digits [4]uint64

		vec[limb].StoreArray(&digits)

		for lane, digit := range digits {
			if digit > vecMask {
				t.Fatalf("limb %d of lane %d is %#x, not normalized", limb, lane, digit)
			}

			res[lane].Lsh(res[lane], vecRadix).Add(res[lane], new(big.Int).SetUint64(digit))
		}
	}

	return res
}

// randBelow returns a random integer in [0, bound·p), biased towards the
// ends of the range.
func randBelow(rnd *testRand, bound int64) *big.Int {
	limit := new(big.Int).Mul(prime(), big.NewInt(bound))

	switch rnd.below(edgeCaseOdds) {
	case 0:
		return new(big.Int).SetUint64(rnd.below(edgeCaseCount))
	case 1:
		return limit.Sub(limit, new(big.Int).SetUint64(1+rnd.below(edgeCaseCount)))
	default:
		return new(big.Int).Mod(new(big.Int).SetBytes(rnd.bytes(fpSize+limbBytes)), limit)
	}
}

func TestVfpArithmetic(t *testing.T) {
	t.Parallel()
	skipWithoutAVX2(t)

	rnd := newTestRand(t.Name())
	vecR := new(big.Int).Lsh(big.NewInt(1), vecRadix*vecLimbs)
	vecRInv := new(big.Int).ModInverse(vecR, prime())
	outBound := new(big.Int).Mul(prime(), big.NewInt(vecMulOutBound))

	for range 300 {
		var lhs, rhs [4]*big.Int
		for lane := range lhs {
			lhs[lane], rhs[lane] = randBelow(rnd, vecMulInBound), randBelow(rnd, vecMulInBound)
		}

		vecX, vecY := vecFromBig(&lhs), vecFromBig(&rhs)

		var prod, square vfp

		prod.mul(&vecX, &vecY)
		square.square(&vecX)
		vecX.mul(&vecX, &vecX) // aliased

		gotProd, gotSq, gotAliased := vecToBig(t, &prod), vecToBig(t, &square), vecToBig(t, &vecX)

		for lane := range lhs {
			want := new(big.Int).Mul(lhs[lane], rhs[lane])
			want.Mul(want, vecRInv).Mod(want, prime())
			wantSq := new(big.Int).Mul(lhs[lane], lhs[lane])
			wantSq.Mul(wantSq, vecRInv).Mod(wantSq, prime())

			for _, res := range []struct {
				op        string
				got, want *big.Int
			}{
				{"mul", gotProd[lane], want},
				{"square", gotSq[lane], wantSq},
				{"mul (aliased)", gotAliased[lane], wantSq},
			} {
				if res.got.Cmp(outBound) >= 0 {
					t.Fatalf("%s(%x, %x) = %x, not below 2p", res.op, lhs[lane], rhs[lane], res.got)
				}

				if new(big.Int).Mod(res.got, prime()).Cmp(res.want) != 0 {
					t.Fatalf("%s(%x, %x) = %x, want %x mod p", res.op, lhs[lane], rhs[lane], res.got, res.want)
				}
			}
		}
	}
}

func TestVfpConversions(t *testing.T) {
	t.Parallel()
	skipWithoutAVX2(t)

	rnd := newTestRand(t.Name())

	for range 100 {
		var elems [4]fp
		for lane := range elems {
			elems[lane] = fromBig(t, randBig(rnd))
		}

		var vec vfp

		vec.set(&elems)

		if vec.elements() != elems {
			t.Fatal("elements ∘ set is not the identity")
		}

		vec.broadcast(&elems[0])

		if got := vec.elements(); got != [4]fp{elems[0], elems[0], elems[0], elems[0]} {
			t.Fatal("broadcast did not copy the element to every lane")
		}

		// elements reduces values in [p, 2p).
		var unreduced [4]*big.Int
		for lane := range unreduced {
			unreduced[lane] = new(big.Int).Add(fpBig(&elems[lane]), prime())
		}

		vec = vecFromBig(&unreduced)
		if vec.elements() != elems {
			t.Fatal("elements did not reduce values in [p, 2p)")
		}
	}
}

// fpBig returns the limbs of elem, the Montgomery form of an element, as an
// integer.
func fpBig(elem *fp) *big.Int {
	res := new(big.Int)
	for limb := len(elem.l) - 1; limb >= 0; limb-- {
		res.Lsh(res, limbBits).Add(res, new(big.Int).SetUint64(elem.l[limb]))
	}

	return res
}

func TestVtheta4Hadamard(t *testing.T) {
	t.Parallel()
	skipWithoutAVX2(t)

	outBound := new(big.Int).Mul(prime(), big.NewInt(vecMulInBound))

	for _, coords := range hadamardCases(newTestRand(t.Name())) {
		var vec vtheta4
		for grp := range vec {
			vec[grp] = vecFromBig((*[4]*big.Int)(coords[4*grp:]))
		}

		vec.hadamard()

		for grp := range vec {
			for lane, got := range vecToBig(t, &vec[grp]) {
				out := 4*grp + lane
				want := hadamardBig(&coords, out)

				if got.Sign() < 0 || got.Cmp(outBound) >= 0 {
					t.Fatalf("coordinate %d = %x, not in [0, 48p)", out, got)
				}

				diff := new(big.Int).Sub(got, want)
				if diff.Mod(diff, prime()).Sign() != 0 {
					t.Fatalf("coordinate %d = %x, want %x mod p", out, got, want)
				}
			}
		}
	}
}

// hadamardCases returns inputs for the vector Hadamard transform: random
// coordinates below 2p, and the extremes: all zero, all 2p − 1, and 2p − 1
// at every other coordinate, which makes some outputs as small as possible.
func hadamardCases(rnd *testRand) [][16]*big.Int {
	const randomCases = 100

	cases := make([][16]*big.Int, 0, randomCases)

	for range randomCases {
		var coords [16]*big.Int
		for idx := range coords {
			coords[idx] = randBelow(rnd, vecMulOutBound)
		}

		cases = append(cases, coords)
	}

	maxCoord := new(big.Int).Lsh(prime(), 1)
	maxCoord.Sub(maxCoord, big.NewInt(1))

	for _, pattern := range []uint{0, 0xffff, 0xaaaa} {
		var coords [16]*big.Int
		for idx := range coords {
			coords[idx] = new(big.Int).Mul(maxCoord, big.NewInt(int64(pattern>>idx&1)))
		}

		cases = append(cases, coords)
	}

	return cases
}

// hadamardBig returns coordinate dst of the Hadamard transform of coords,
// without reduction.
func hadamardBig(coords *[16]*big.Int, dst int) *big.Int {
	res := new(big.Int)

	for src, coord := range coords {
		// The sign of coordinate src in output dst is (−1)^popcount(dst & src).
		if bits.OnesCount(uint(dst&src))%2 == 1 {
			res.Sub(res, coord)
		} else {
			res.Add(res, coord)
		}
	}

	return res
}

func randTheta4(t *testing.T, rnd *testRand) theta4 {
	t.Helper()

	var res theta4
	for idx := range res {
		res[idx] = fromBig(t, randBig(rnd))
	}

	return res
}

func TestVtheta4MatchesScalar(t *testing.T) {
	t.Parallel()
	skipWithoutAVX2(t)

	rnd := newTestRand(t.Name())
	rhoInv := vecRhoInvPow(1)

	const doublings = 3

	for range 20 {
		domain := theta4Structure{
			null:      randTheta4(t, rnd),
			invNull:   randTheta4(t, rnd),
			invDualSq: randTheta4(t, rnd),
		}
		point := randTheta4(t, rnd)

		vecDomain := newVtheta4Structure(&domain)

		var vecPoint vtheta4

		vecPoint.set(&point)
		domain.doubleN(&point, doublings)

		for range doublings {
			vecDomain.double(&vecPoint)
		}

		if vecPoint.scaled(&rhoInv) != point {
			t.Fatal("vector doubling ≠ scalar doubling")
		}

		gen1, gen2 := randTheta4(t, rnd), randTheta4(t, rnd)
		images := []theta4{randTheta4(t, rnd), randTheta4(t, rnd), randTheta4(t, rnd)}
		vecGens, vecImages := make([]vtheta4, 2), make([]vtheta4, len(images))

		vecGens[0].set(&gen1)
		vecGens[1].set(&gen2)

		for idx := range images {
			vecImages[idx].set(&images[idx])
		}

		want := twoIsogeny4(&gen1, &gen2, images)
		if got := twoIsogeny4Vec(&vecGens[0], &vecGens[1], vecImages); got != want {
			t.Fatal("vector isogeny codomain ≠ scalar codomain")
		}

		for idx := range images {
			if vecImages[idx].scaled(&rhoInv) != images[idx] {
				t.Fatalf("image %d: vector isogeny ≠ scalar isogeny", idx)
			}
		}
	}
}

func BenchmarkTheta4Double(b *testing.B) {
	skipWithoutAVX2(b)

	rnd := newTestRand(b.Name())

	var (
		domain theta4Structure
		point  theta4
	)

	for idx := range point {
		domain.invNull[idx].setUint64(rnd.below(math.MaxUint64))
		domain.invDualSq[idx].setUint64(rnd.below(math.MaxUint64))
		point[idx].setUint64(rnd.below(math.MaxUint64))
	}

	b.Run("scalar", func(b *testing.B) {
		for b.Loop() {
			domain.double(&point)
		}
	})

	vecDomain := newVtheta4Structure(&domain)

	var vecPoint vtheta4

	vecPoint.set(&point)
	b.Run("avx2", func(b *testing.B) {
		for b.Loop() {
			vecDomain.double(&vecPoint)
		}
	})
}

func BenchmarkVfp(b *testing.B) {
	skipWithoutAVX2(b)

	rnd := newTestRand(b.Name())

	var elems [4]fp
	for lane := range elems {
		elems[lane].setUint64(rnd.below(math.MaxUint64))
	}

	var vec vfp

	vec.set(&elems)
	b.Run("mul", func(b *testing.B) {
		for b.Loop() {
			vec.mul(&vec, &vec)
		}
	})
	b.Run("square", func(b *testing.B) {
		for b.Loop() {
			vec.square(&vec)
		}
	})
	b.Run("set", func(b *testing.B) {
		for b.Loop() {
			vec.set(&elems)
		}
	})
	b.Run("elements", func(b *testing.B) {
		for b.Loop() {
			elems = vec.elements()
		}
	})
}
