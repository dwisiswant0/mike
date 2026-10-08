// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// This file generates fpvec_arith_amd64.go: the constants and the
// straight-line arithmetic of the AVX2 field elements, which hold four
// elements of GF(p) in radix 2^r. See vfp in internal/p308 for the
// representation and its bounds.

const (
	// The radixes to try, largest first.
	maxVecRadix = 30
	minVecRadix = 26

	// mulOperandBits is the operand width of VPMULUDQ, which multiplies
	// the limbs.
	mulOperandBits = 32

	// laneBits is the width of a vector lane, which holds a column sum of
	// a product.
	laneBits = 64

	// The vector Hadamard transform adds hadamardOffset·p to keep its
	// outputs nonnegative, and maps inputs below 2p to outputs below
	// hadamardBound·p. See vtheta4.hadamard in internal/p308.
	hadamardOffset = 16
	hadamardBound  = 48
)

var errNoVecRadix = errors.New("no radix fits the vector arithmetic")

//go:embed vec.go.tmpl
var vecTemplate string

// vecArith holds the values substituted into the vector arithmetic
// template.
type vecArith struct {
	Pkg          string
	C, F         int
	Radix, Limbs int
	TopLimb      int    // p + 1 = Top·2^(Radix·TopLimb)
	Top          string // below 2^32
	Offset       string // hadamardOffset·p in radix 2^Radix, as a Go array literal
	RhoInv       string // 2^(Radix·Limbs) mod p, as a Go array literal of 64-bit limbs
	Mul, Square  string
}

// vecLayout is the shape of the vector representation of GF(p): each element
// has the given number of limbs of radix 2^radix, and
// p + 1 = top·2^(radix·topLimb).
type vecLayout struct {
	radix, limbs, topLimb int
	top                   *big.Int
}

// genVecArith returns fpvec_arith_amd64.go for the prime of set.
func genVecArith(set *paramSet) ([]byte, error) {
	modulus := new(big.Int).Lsh(big.NewInt(int64(set.C)), uint(set.F))
	modulus.Sub(modulus, big.NewInt(1))
	size := (modulus.BitLen() + limbBits - 1) / limbBits

	layout, ok := chooseVecLayout(set, modulus, size)
	if !ok {
		return nil, fmt.Errorf("%s: %w", set.Name, errNoVecRadix)
	}

	vecR := new(big.Int).Lsh(big.NewInt(1), uint(layout.radix*layout.limbs))
	offset := new(big.Int).Mul(modulus, big.NewInt(hadamardOffset))

	return execute("fpvec_arith_amd64.go", vecTemplate, &vecArith{
		Pkg:     set.Pkg(),
		C:       set.C,
		F:       set.F,
		Radix:   layout.radix,
		Limbs:   layout.limbs,
		TopLimb: layout.topLimb,
		Top:     fmt.Sprintf("%#x", layout.top),
		Offset:  radixLimbs(offset, layout.radix, layout.limbs),
		RhoInv:  limbs(new(big.Int).Mod(vecR, modulus), size),
		Mul:     genVecMul(layout.limbs, layout.topLimb),
		Square:  genVecSquare(layout.limbs, layout.topLimb),
	})
}

// chooseVecLayout returns the layout with the fewest limbs, and then the
// largest radix, that meets the bounds that vfp relies on. The prime
// modulus has size 64-bit limbs.
func chooseVecLayout(set *paramSet, modulus *big.Int, size int) (vecLayout, bool) {
	var (
		best  vecLayout
		found bool
	)

	for radix := maxVecRadix; radix >= minVecRadix; radix-- {
		layout, ok := newVecLayout(set, modulus, size, radix)
		if ok && (!found || layout.limbs < best.limbs) {
			best, found = layout, true
		}
	}

	return best, found
}

// newVecLayout returns the layout of radix 2^radix with the fewest limbs
// that meets the bounds, or false if there is none.
func newVecLayout(set *paramSet, modulus *big.Int, size, radix int) (vecLayout, bool) {
	layout := vecLayout{radix: radix, limbs: 0, topLimb: set.F / radix, top: nil}
	layout.top = new(big.Int).Lsh(big.NewInt(int64(set.C)), uint(set.F-radix*layout.topLimb))

	// The reduction multiplies q < 2^radix by top with VPMULUDQ.
	if layout.top.BitLen() > mulOperandBits {
		return layout, false
	}

	// Montgomery multiplication of values below 48p must return a value
	// below 2p: (48p)²/R_v + p < 2p, that is 48²·p < R_v.
	minR := new(big.Int).Mul(modulus, big.NewInt(hadamardBound*hadamardBound))
	limbMax := new(big.Int).Lsh(big.NewInt(1), uint(radix))
	limbMax.Sub(limbMax, big.NewInt(1))

	for layout.limbs = layout.topLimb + 1; ; layout.limbs++ {
		// A column of the product sums at most limbs products of two
		// limbs, the reduction term q·top, and the carry from the column
		// below. The sum must fit in a 64-bit lane.
		column := new(big.Int).Mul(limbMax, limbMax)
		column.Mul(column, big.NewInt(int64(layout.limbs)))
		column.Add(column, new(big.Int).Mul(limbMax, layout.top))
		column.Add(column, new(big.Int).Lsh(big.NewInt(1), uint(laneBits-radix)))

		if column.BitLen() > laneBits {
			return layout, false
		}

		vecR := new(big.Int).Lsh(big.NewInt(1), uint(radix*layout.limbs))
		// The conversions assume that every 64-bit limb of an element
		// lies within the vector limbs.
		if vecR.Cmp(minR) > 0 && radix*layout.limbs >= limbBits*size {
			return layout, true
		}
	}
}

// radixLimbs formats val as a Go array literal of count little-endian limbs
// of radix 2^radix. The top limb takes the remaining bits.
func radixLimbs(val *big.Int, radix, count int) string {
	mask := new(big.Int).Lsh(big.NewInt(1), uint(radix))
	mask.Sub(mask, big.NewInt(1))

	rest := new(big.Int).Set(val)
	digits := make([]string, count)

	for idx := range digits {
		digit := rest
		if idx < count-1 {
			digit = new(big.Int).And(rest, mask)
		}

		digits[idx] = fmt.Sprintf("%#x", digit)
		rest = new(big.Int).Rsh(rest, uint(radix))
	}

	return "{" + strings.Join(digits, ", ") + "}"
}

// genVecMul emits z = x·y/R_v mod p for vectors, in product-scanning form.
func genVecMul(count, topLimb int) string {
	var emit emitter

	emit.linef("mask := archsimd.BroadcastUint64x4(vecMask)")
	emit.linef("top := archsimd.BroadcastUint64x4(vecTop).ReshapeToUint32s()")

	for limb := range count {
		emit.linef("x%d := x[%d].ReshapeToUint32s()", limb, limb)
	}

	for limb := range count {
		emit.linef("y%d := y[%d].ReshapeToUint32s()", limb, limb)
	}

	emitVecColumns(&emit, count, topLimb, func(col int) []string {
		var terms []string
		for idx := max(0, col-count+1); idx <= min(col, count-1); idx++ {
			terms = append(terms, fmt.Sprintf("x%d.MulWidenEven(y%d)", idx, col-idx))
		}

		return terms
	})

	return emit.String()
}

// genVecSquare emits z = x²/R_v mod p for vectors. Each cross product is
// computed once, with one factor doubled: 2x[i] < 2^(radix+1) still fits
// in the 32-bit operand.
func genVecSquare(count, topLimb int) string {
	var emit emitter

	emit.linef("mask := archsimd.BroadcastUint64x4(vecMask)")
	emit.linef("top := archsimd.BroadcastUint64x4(vecTop).ReshapeToUint32s()")

	for limb := range count {
		emit.linef("x%d := x[%d].ReshapeToUint32s()", limb, limb)
	}

	for limb := range count - 1 {
		emit.linef("d%d := x[%d].ShiftAllLeft(1).ReshapeToUint32s()", limb, limb)
	}

	emitVecColumns(&emit, count, topLimb, func(col int) []string {
		var terms []string

		for idx := max(0, col-count+1); idx <= min(col, count-1); idx++ {
			other := col - idx

			switch {
			case idx < other:
				terms = append(terms, fmt.Sprintf("d%d.MulWidenEven(x%d)", idx, other))
			case idx == other:
				terms = append(terms, fmt.Sprintf("x%d.MulWidenEven(x%d)", idx, idx))
			}
		}

		return terms
	})

	return emit.String()
}

// emitVecColumns emits the columns of a product, given the products of
// each column, interleaved with the Montgomery reduction.
//
// With p + 1 = top·2^(radix·topLimb), p ≡ −1 mod 2^radix, so the reduction
// digit of column i is q_i = acc mod 2^radix. Adding q_i·p at column i is
// subtracting q_i there, which clears the low bits, and adding q_i·top at
// column i + topLimb. So column i passes acc >> radix up as its carry, and
// the columns from count on, divided by R_v, form the result.
func emitVecColumns(emit *emitter, count, topLimb int, products func(col int) []string) {
	emit.linef("var acc, carry archsimd.Uint64x4")
	emit.declareVec("q", count)

	for col := 0; col <= productLimbs*count-productLimbs; col++ {
		terms := products(col)
		if col >= topLimb && col-topLimb < count {
			terms = append(terms, fmt.Sprintf("q%d.ReshapeToUint32s().MulWidenEven(top)", col-topLimb))
		}

		if col > 0 {
			terms = append(terms, "carry")
		}

		var sum strings.Builder

		sum.WriteString(terms[0])

		for _, term := range terms[1:] {
			fmt.Fprintf(&sum, ".Add(%s)", term)
		}

		emit.linef("acc = %s", sum.String())

		if col < count {
			emit.linef("q%d = acc.And(mask)", col)
		} else {
			emit.linef("z[%d] = acc.And(mask)", col-count)
		}

		emit.linef("carry = acc.ShiftAllRight(vecRadix)")
	}

	emit.linef("z[%d] = carry", count-1)
}

// declareVec emits the declaration of the vector variables prefix0,
// prefix1, and so on, up to prefix(count−1).
func (e *emitter) declareVec(prefix string, count int) {
	names := make([]string, count)
	for idx := range names {
		names[idx] = fmt.Sprintf("%s%d", prefix, idx)
	}

	e.linef("var %s archsimd.Uint64x4", strings.Join(names, ", "))
}
