// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// This file generates fp_arith.go: the field constants and the straight-line
// field arithmetic for one prime.

const (
	limbBits = 64 // the size of a limb in bits
	byteBits = 8  // the size of a byte in bits

	// productLimbs·N is the number of limbs of a product of two N-limb
	// numbers.
	productLimbs = 2

	// sqrtShift gives the square root exponent (p + 1)/4 as
	// (p + 1) >> sqrtShift, for p ≡ 3 mod 4.
	sqrtShift = 2

	// primalityRounds is the number of Miller–Rabin rounds for checking that
	// a modulus is prime.
	primalityRounds = 32
)

var (
	errNotPrime         = errors.New("modulus is not prime")
	errUnsupportedShape = errors.New("unsupported prime shape")
)

//go:embed arith.go.tmpl
var arithTemplate string

// arith holds the values substituted into the arithmetic template.
type arith struct {
	Pkg    string
	C, F   int
	N      int // number of 64-bit limbs
	Bytes  int // encoded length in bytes
	Bits   int // bit length of p
	Consts fieldConstants
	Code   fieldCode
}

// fieldConstants holds the field constants, as Go array literals of limbs,
// except for PTop.
type fieldConstants struct {
	Modulus string
	R, R2   string // Montgomery constants R and R² mod p
	ExpInv  string // p − 2
	ExpSqrt string // (p + 1) / 4
	ExpLeg  string // (p − 1) / 2
	PTop    string // the top limb of p + 1
}

// fieldCode holds the bodies of the generated arithmetic functions.
type fieldCode struct {
	Add, Sub, Mul, Square, FromMont string
}

// genArith returns fp_arith.go for the prime of set.
//
// Every MIKE prime has the form p = c·2^f − 1 with f ≥ 64·(N−1), where N is
// the number of 64-bit limbs. So p+1 has a single nonzero limb, the top one,
// and p ≡ −1 mod 2^64, and Montgomery reduction needs one 64×64-bit
// multiplication per limb instead of N.
func genArith(set *paramSet) ([]byte, error) {
	modulus := new(big.Int).Lsh(big.NewInt(int64(set.C)), uint(set.F))
	modulus.Sub(modulus, big.NewInt(1))

	if !modulus.ProbablyPrime(primalityRounds) {
		return nil, fmt.Errorf("%s: %w", set.Name, errNotPrime)
	}

	bitLen := modulus.BitLen()
	size := (bitLen + limbBits - 1) / limbBits
	// The reduction shortcut needs p+1 to vanish below the top limb, and
	// the lazy carry handling in add needs 2p < 2^(64N).
	if set.F < limbBits*(size-1) || bitLen%limbBits == 0 {
		return nil, fmt.Errorf("%s: %w", set.Name, errUnsupportedShape)
	}

	return execute("fp_arith.go", arithTemplate, &arith{
		Pkg:    set.Pkg(),
		C:      set.C,
		F:      set.F,
		N:      size,
		Bytes:  (bitLen + byteBits - 1) / byteBits,
		Bits:   bitLen,
		Consts: newFieldConstants(modulus, size),
		Code: fieldCode{
			Add:      genAdd(size),
			Sub:      genSub(size),
			Mul:      genMul(size),
			Square:   genSquare(size),
			FromMont: genFromMont(size),
		},
	})
}

// newFieldConstants returns the constants for the prime modulus, which has
// size limbs.
func newFieldConstants(modulus *big.Int, size int) fieldConstants {
	one := big.NewInt(1)
	two := new(big.Int).Add(one, one)
	plusOne := new(big.Int).Add(modulus, one)
	minusOne := new(big.Int).Sub(modulus, one)

	montR := new(big.Int).Lsh(one, uint(limbBits*size))
	montR.Mod(montR, modulus)

	montR2 := new(big.Int).Mul(montR, montR)
	montR2.Mod(montR2, modulus)

	return fieldConstants{
		Modulus: limbs(modulus, size),
		R:       limbs(montR, size),
		R2:      limbs(montR2, size),
		ExpInv:  limbs(new(big.Int).Sub(modulus, two), size),
		ExpSqrt: limbs(new(big.Int).Rsh(plusOne, sqrtShift), size),
		ExpLeg:  limbs(new(big.Int).Rsh(minusOne, 1), size),
		PTop:    fmt.Sprintf("%#x", new(big.Int).Rsh(plusOne, uint(limbBits*(size-1)))),
	}
}

// limbs formats val as a Go array literal of size little-endian 64-bit
// limbs.
func limbs(val *big.Int, size int) string {
	mask := new(big.Int).SetUint64(math.MaxUint64)
	rest := new(big.Int).Set(val)
	words := make([]string, size)

	for idx := range words {
		words[idx] = fmt.Sprintf("%#016x", new(big.Int).And(rest, mask).Uint64())
		rest.Rsh(rest, limbBits)
	}

	return "{" + strings.Join(words, ", ") + "}"
}

// emitter accumulates generated statements.
type emitter struct{ lines []string }

func (e *emitter) String() string { return strings.Join(e.lines, "") }

// linef emits one statement.
func (e *emitter) linef(format string, args ...any) {
	e.lines = append(e.lines, "\t"+fmt.Sprintf(format, args...)+"\n")
}

// declare emits the declaration of the uint64 variables prefix0, prefix1,
// and so on, up to prefix(count−1).
func (e *emitter) declare(prefix string, count int) {
	names := make([]string, count)
	for idx := range names {
		names[idx] = fmt.Sprintf("%s%d", prefix, idx)
	}

	e.linef("var %s uint64", strings.Join(names, ", "))
}

// carry returns the carry-in argument for limb i of an Add64 or Sub64 chain.
func carry(i int, name string) string {
	if i == 0 {
		return "0"
	}

	return name
}

// genAdd emits z = x + y mod p. Because 2p < 2^(64N), x + y never overflows
// N limbs, so a conditional subtraction of p is enough.
func genAdd(size int) string {
	var emit emitter

	emit.linef("var c, b uint64")

	for limb := range size {
		emit.linef("t%d, c := bits.Add64(x.l[%d], y.l[%d], %s)", limb, limb, limb, carry(limb, "c"))
	}

	subtractModulus(&emit, size, "z.l")

	return emit.String()
}

// subtractModulus emits z = t − p if t ≥ p, and z = t otherwise, where dst
// is the limb array of z.
func subtractModulus(emit *emitter, size int, dst string) {
	for limb := range size {
		emit.linef("u%d, b := bits.Sub64(t%d, fpP[%d], %s)", limb, limb, limb, carry(limb, "b"))
	}

	emit.linef("m := -b")

	for limb := range size {
		emit.linef("%s[%d] = u%d ^ (m & (u%d ^ t%d))", dst, limb, limb, limb, limb)
	}
}

// genSub emits z = x − y mod p.
func genSub(size int) string {
	var emit emitter

	emit.linef("var b, c uint64")

	for limb := range size {
		emit.linef("t%d, b := bits.Sub64(x.l[%d], y.l[%d], %s)", limb, limb, limb, carry(limb, "b"))
	}

	emit.linef("m := -b")

	for limb := range size {
		emit.linef("z.l[%d], c = bits.Add64(t%d, fpP[%d]&m, %s)", limb, limb, limb, carry(limb, "c"))
	}

	return emit.String()
}

// genMul emits Montgomery multiplication z = x·y/R mod p in the CIOS form,
// specialized for p+1 = pTop·2^(64(N−1)).
//
// Each outer step adds x·y[i] to the accumulator t, then adds m·p with
// m = t[0]. Writing p = pTop·2^(64(N−1)) − 1, this is
// t − m + m·pTop·2^(64(N−1)): the low limb cancels exactly, so the division
// by 2^64 is a limb shift followed by adding the two-limb product m·pTop at
// limbs N−2 and N−1. The accumulator stays below 2p, so N+1 limbs suffice.
func genMul(size int) string {
	var emit emitter

	emit.linef("var c uint64")
	emit.declare("t", size+1)
	emit.declare("h", size)
	emit.declare("l", size)
	emit.declare("r", size+1)

	for row := range size {
		emitMulRow(&emit, size, row)
	}

	emit.linef("var b uint64")
	subtractModulus(&emit, size, "z")

	return emit.String()
}

// emitMulRow emits the outer step of genMul for y[row].
func emitMulRow(emit *emitter, size, row int) {
	top := size - 1

	emit.linef("// Row %d: t += x·y[%d].", row, row)

	for col := range size {
		emit.linef("h%d, l%d = bits.Mul64(x[%d], y[%d])", col, col, col, row)
	}

	emit.linef("r0 = l0")

	for col := 1; col < size; col++ {
		emit.linef("r%d, c = bits.Add64(l%d, h%d, %s)", col, col, col-1, carry(col-1, "c"))
	}

	emit.linef("r%d, _ = bits.Add64(h%d, 0, c)", size, top)

	for col := 0; col <= size; col++ {
		emit.linef("t%d, c = bits.Add64(t%d, r%d, %s)", col, col, col, carry(col, "c"))
	}

	emit.linef("// Reduce: t = (t + t0·p) / 2^64.")
	emit.linef("h0, l0 = bits.Mul64(t0, fpPTop)")

	for col := range size {
		emit.linef("t%d = t%d", col, col+1)
	}

	emit.linef("t%d = 0", size)
	emit.linef("t%d, c = bits.Add64(t%d, l0, 0)", top-1, top-1)
	emit.linef("t%d, _ = bits.Add64(t%d, h0, c)", top, top)
}

// genSquare emits Montgomery squaring z = x²/R mod p. It computes the full
// 2N-limb square T, using each cross product once, and then reduces it.
func genSquare(size int) string {
	var emit emitter

	emit.linef("var c uint64")
	emit.declare("t", productLimbs*size)
	emit.declare("h", size)
	emit.declare("l", size)
	emit.declare("r", size)

	emitSquareCross(&emit, size)
	emitSquareDiagonal(&emit, size)
	emitSquareReduce(&emit, size)

	return emit.String()
}

// emitSquareCross emits the sum of the cross products x[i]·x[j] for i < j,
// at limb i + j of T.
//
// Row i adds x[i]·(x[i+1], …, x[N−1]) at limb 2i+1. The row is first formed
// as a (k+1)-limb number r, for k = N−1−i products, then added with one
// carry chain. The carry out lands in limb i+N+1, which no earlier row has
// reached.
func emitSquareCross(emit *emitter, size int) {
	for row := range size - 1 {
		count := size - 1 - row
		start := productLimbs*row + 1

		emit.linef("// Cross products with x[%d].", row)

		for col := range count {
			emit.linef("h%d, l%d = bits.Mul64(x[%d], x[%d])", col, col, row, row+1+col)
		}

		emit.linef("r0 = l0")

		for col := 1; col < count; col++ {
			emit.linef("r%d, c = bits.Add64(l%d, h%d, %s)", col, col, col-1, carry(col-1, "c"))
		}

		if count == 1 {
			emit.linef("r1 = h0")
		} else {
			emit.linef("r%d, _ = bits.Add64(h%d, 0, c)", count, count-1)
		}

		for col := 0; col <= count; col++ {
			emit.linef("t%d, c = bits.Add64(t%d, r%d, %s)", start+col, start+col, col, carry(col, "c"))
		}

		emit.linef("t%d = c", row+size+1)
	}
}

// emitSquareDiagonal emits the doubling of the cross products and the
// addition of the squares x[i]², which completes T.
func emitSquareDiagonal(emit *emitter, size int) {
	emit.linef("// Double the cross products; t0 is zero.")

	for limb := productLimbs*size - 1; limb > 1; limb-- {
		emit.linef("t%d = t%d<<1 | t%d>>63", limb, limb, limb-1)
	}

	emit.linef("t1 <<= 1")

	emit.linef("// Add the squares of the limbs.")

	for limb := range size {
		emit.linef("h%d, l%d = bits.Mul64(x[%d], x[%d])", limb, limb, limb, limb)
	}

	for limb := range size {
		low := productLimbs * limb
		emit.linef("t%d, c = bits.Add64(t%d, l%d, %s)", low, low, limb, carry(low, "c"))
		emit.linef("t%d, c = bits.Add64(t%d, h%d, c)", low+1, low+1, limb)
	}
}

// emitSquareReduce emits the Montgomery reduction of T.
//
// Montgomery reduction adds M·p to T, for the N-limb M that clears the low N
// limbs, and keeps the high limbs. With p+1 = pTop·2^(64(N−1)), this sum is
// T − M + pTop·M·2^(64(N−1)). The term pTop·M·2^(64(N−1)) only touches limbs
// N−1 and above, so m_j = T[j] for j < N−1, and
// m_{N−1} = T[N−1] + lo(m_0·pTop) accounts for the one term that reaches
// limb N−1. Then the low N limbs of T + pTop·M·2^(64(N−1)) equal M, so
// subtracting M just clears them: the result is the high N limbs of
// T + pTop·M·2^(64(N−1)). It is below 2p because T < p·R.
func emitSquareReduce(emit *emitter, size int) {
	top := size - 1

	emit.linef("// Reduce: add pTop·M at limb N−1 and keep the high N limbs.")
	emit.linef("h0, l0 = bits.Mul64(t0, fpPTop)")
	emit.linef("m := t%d + l0 // the top limb of M", top)

	for limb := 1; limb < size; limb++ {
		digit := fmt.Sprintf("t%d", limb)
		if limb == top {
			digit = "m"
		}

		emit.linef("h%d, l%d = bits.Mul64(%s, fpPTop)", limb, limb, digit)
	}
	// pTop·M has N+1 limbs: l0, then r_j = l_j + h_{j−1} for 0 < j < N,
	// then rTop = h_{N−1} plus the carry.
	emit.linef("var c2, rTop uint64")

	for limb := 1; limb < size; limb++ {
		emit.linef("r%d, c2 = bits.Add64(l%d, h%d, %s)", limb, limb, limb-1, carry(limb-1, "c2"))
	}

	emit.linef("rTop, _ = bits.Add64(h%d, 0, c2)", top)
	emit.linef("_, c = bits.Add64(t%d, l0, 0)", top)

	for limb := 1; limb < size; limb++ {
		emit.linef("t%d, c = bits.Add64(t%d, r%d, c)", top+limb, top+limb, limb)
	}

	emit.linef("t%d, _ = bits.Add64(t%d, rTop, c)", productLimbs*size-1, productLimbs*size-1)

	emit.linef("var b uint64")

	for limb := range size {
		emit.linef("u%d, b := bits.Sub64(t%d, fpP[%d], %s)", limb, size+limb, limb, carry(limb, "b"))
	}

	emit.linef("msk := -b")

	for limb := range size {
		emit.linef("z[%d] = u%d ^ (msk & (u%d ^ t%d))", limb, limb, limb, size+limb)
	}
}

// genFromMont emits the conversion out of Montgomery form, x/R mod p. It is
// the multiplication above with y = 1; the result needs no final
// subtraction because x < p.
func genFromMont(size int) string {
	var emit emitter

	top := size - 1

	emit.linef("var c, h, l uint64")
	emit.linef("t := x.l")

	for range size {
		emit.linef("h, l = bits.Mul64(t[0], fpPTop)")
		emit.linef("copy(t[:], t[1:])")
		emit.linef("t[%d] = 0", top)
		emit.linef("t[%d], c = bits.Add64(t[%d], l, 0)", top-1, top-1)
		emit.linef("t[%d], _ = bits.Add64(t[%d], h, c)", top, top)
	}

	emit.linef("return t")

	return emit.String()
}
