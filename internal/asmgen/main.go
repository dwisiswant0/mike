// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

// Command asmgen generates fp_amd64.s for each prime in
// internal/gen/params.txt: the amd64 assembly of the multiplication and
// squaring in GF(p) and GF(p²), and of the Hadamard transform of theta points.
// Run it with "go generate" in the module root.
//
// It is a module of its own, so that the mike module doesn't depend on avo.
package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mmcloughlin/avo/attr"    //nolint:depguard // This module exists to use avo.
	"github.com/mmcloughlin/avo/build"   //nolint:depguard // See above.
	"github.com/mmcloughlin/avo/ir"      //nolint:depguard // See above.
	"github.com/mmcloughlin/avo/operand" //nolint:depguard // See above.
	"github.com/mmcloughlin/avo/pass"    //nolint:depguard // See above.
	"github.com/mmcloughlin/avo/printer" //nolint:depguard // See above.
	"github.com/mmcloughlin/avo/reg"     //nolint:depguard // See above.
)

const (
	paramsFile = "../gen/params.txt" // relative to this directory
	limbBits   = 64
	limbBytes  = 8
	filePerm   = 0o600

	// allocatableRegs is the number of general-purpose registers that avo
	// allocates: all but RSP and RBP.
	allocatableRegs = 14

	// rowRegs is the number of registers that mulRows has for the
	// accumulator limbs and the pointer to x: the allocatable registers, less
	// RDX and the two halves of a product.
	rowRegs = allocatableRegs - 3

	// maxPointerLimbs is the largest number of limbs for which the Hadamard
	// transform keeps the pointer to the point in a register: the N limbs of a
	// sum or difference, the pointer, a mask, and the top limb of p take at
	// most the 14 allocatable registers.
	maxPointerLimbs = 11

	// maxFp2Limbs is the largest number of limbs for which fp2MulAsm and
	// fp2SquareAsm compute the products themselves. Above it, they call
	// fpMulAsm instead: with 12 limbs, GenerateKey was about 5% slower with
	// the products inline on an AMD EPYC 7763, although the functions were
	// faster in isolation.
	maxFp2Limbs = 10

	// mulArgs is the number of pointer arguments of fpMulAsm.
	mulArgs = 3

	// The signatures of the functions, given the number of limbs.
	mulSignature       = "func(z, x, y *[%[1]d]uint64)"
	squareSignature    = "func(z, x *[%[1]d]uint64)"
	fp2MulSignature    = "func(z, x, y *[2][%[1]d]uint64)"
	fp2SquareSignature = "func(z, x *[2][%[1]d]uint64)"
	hadamardSignature  = "func(p *[16][%[1]d]uint64)"

	// thetaCoords is the number of coordinates of a theta point in dimension 4.
	thetaCoords = 16

	// productLimbs·N is the number of limbs of a product of two N-limb
	// numbers.
	productLimbs = 2

	// CPUID leaf 7 reports the BMI2 and ADX extensions in these bits of EBX.
	cpuidLeaf = 7
	cpuidBMI2 = 1 << 8
	cpuidADX  = 1 << 19
)

var errParamSet = errors.New("malformed parameter set")

// field describes GF(p) for a prime p = c·2^f − 1.
type field struct {
	pkg   string // the package that holds the field arithmetic
	limbs int
	top   uint64 // the top limb of p + 1; the other limbs are zero
}

func main() {
	fields, err := loadFields()
	if err != nil {
		log.Fatal(err)
	}

	for _, fld := range fields {
		src, err := generate(fld)
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile(fld.asmPath(), src, filePerm)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// asmPath returns the path of the assembly file of fld, relative to this
// directory.
func (fld field) asmPath() string { return filepath.Join("..", fld.pkg, "fp_amd64.s") }

// loadFields returns the fields of the parameter sets in paramsFile, which
// internal/gen reads too.
func loadFields() ([]field, error) {
	text, err := os.ReadFile(paramsFile)
	if err != nil {
		return nil, fmt.Errorf("reading the parameter sets: %w", err)
	}

	var fields []field

	for line := range strings.Lines(string(text)) {
		if strings.HasPrefix(line, "#") {
			continue
		}

		var (
			set                string
			cofactor, exponent int
		)

		_, err := fmt.Sscan(line, &set, &cofactor, &exponent)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", errParamSet, line, err)
		}

		fld, err := newField(cofactor, exponent)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", set, err)
		}

		fields = append(fields, fld)
	}

	return fields, nil
}

// newField returns the field for p = cofactor·2^exponent − 1, after checking
// that the reduction in the assembly applies to it.
func newField(cofactor, exponent int) (field, error) {
	pPlus1 := new(big.Int).Lsh(big.NewInt(int64(cofactor)), uint(exponent))
	bitLen := new(big.Int).Sub(pPlus1, big.NewInt(1)).BitLen()
	limbs := (bitLen + limbBits - 1) / limbBits
	low := limbBits * (limbs - 1)

	// The reduction needs p + 1 = top·2^(64·(N−1)) with a one-limb top, and
	// values below 2p must fit in N limbs.
	top := new(big.Int).Rsh(pPlus1, uint(low))
	if exponent < low || !top.IsUint64() || bitLen >= limbBits*limbs {
		return field{}, fmt.Errorf("%w: unsupported prime %d·2^%d − 1", errParamSet, cofactor, exponent)
	}

	return field{pkg: fmt.Sprintf("p%d", exponent), limbs: limbs, top: top.Uint64()}, nil
}

// generate returns the assembly of fld.
func generate(fld field) ([]byte, error) {
	ctx := build.NewContext()
	ctx.ConstraintExpr("!purego")

	gen := &generator{Context: ctx, field: fld}
	gen.cpuCheck()

	for _, function := range []struct{ name, signature string }{
		{"fpMul", mulSignature},
		{"fpSquare", squareSignature},
		{"fp2Mul", fp2MulSignature},
		{"fp2Square", fp2SquareSignature},
		{"theta4Hadamard", hadamardSignature},
	} {
		gen.dispatch(function.name, function.signature)
	}

	gen.fpMul()
	gen.fpSquare()
	gen.fp2Mul()
	gen.fp2Square()
	gen.hadamard()

	file, err := ctx.Result()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fld.pkg, err)
	}

	err = pass.Compile.Execute(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fld.pkg, err)
	}

	src, err := printer.NewGoAsm(printer.Config{Argv: nil, Name: "internal/asmgen", Pkg: fld.pkg}).Print(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fld.pkg, err)
	}

	return src, nil
}

// generator emits the functions of one field. Both compute a Montgomery
// product x·y/R mod p, where R = 2^(64·N), with the reduction interleaved.
// Because p ≡ −1 mod 2^64, the quotient limb q that clears the low limb of
// the accumulator is that limb itself, and adding q·p = q·(p + 1) − q cancels
// the limb and adds q·top at limbs N − 1 and N above it. The result stays
// below 2p, and a constant-time subtraction of p completes the reduction.
type generator struct {
	*build.Context
	field
}

// begin starts the function name with a signature format that takes the
// number of limbs.
func (g *generator) begin(name, signature, doc string) {
	g.Function(name)
	g.Attributes(attr.NOSPLIT)
	g.SignatureExpr(fmt.Sprintf(signature, g.limbs))
	g.Doc(doc, "The inputs must be below p, and z may alias them.")
}

// cpuCheck emits hasBMI2AndADX, which reports whether the CPU supports MULX,
// ADCX, and ADOX.
func (g *generator) cpuCheck() {
	g.Function("hasBMI2AndADX")
	g.Attributes(attr.NOSPLIT)
	g.SignatureExpr("func() bool")
	g.Doc("hasBMI2AndADX reports whether the CPU supports the BMI2 and ADX extensions.")

	g.XORL(reg.EAX, reg.EAX)
	g.CPUID()
	g.CMPL(reg.EAX, operand.U8(cpuidLeaf)) // the highest basic leaf
	g.JB(operand.LabelRef("unsupported"))

	g.MOVL(operand.U32(cpuidLeaf), reg.EAX)
	g.XORL(reg.ECX, reg.ECX)
	g.CPUID()
	g.ANDL(operand.U32(cpuidBMI2|cpuidADX), reg.EBX)
	g.CMPL(reg.EBX, operand.U32(cpuidBMI2|cpuidADX))
	g.SETEQ(reg.AL)
	g.Store(reg.AL, g.ReturnIndex(0))
	g.RET()

	g.Label("unsupported")
	g.MOVB(operand.U8(0), reg.AL)
	g.Store(reg.AL, g.ReturnIndex(0))
	g.RET()
}

// dispatch emits name, which jumps to nameAsm if the Go variable useAsm is
// set, and to the Go function nameGeneric otherwise. It has no frame, so its
// arguments are those of the function it jumps to.
func (g *generator) dispatch(name, signature string) {
	g.Function(name)
	g.Attributes(attr.NOSPLIT)
	g.SignatureExpr(fmt.Sprintf(signature, g.limbs))
	g.Doc(name + " runs " + name + "Asm on CPUs that support it, and " + name + "Generic otherwise.")

	g.CMPB(symbol("useAsm"), operand.U8(0))
	g.JEQ(operand.LabelRef("generic"))
	g.tailCall(name + "Asm")

	g.Label("generic")
	g.tailCall(name + "Generic")
}

// tailCall emits a jump to the package function name. avo checks that each
// branch targets a label, so the jump is marked as a terminal instruction,
// like RET, instead.
func (g *generator) tailCall(name string) {
	g.Instruction(&ir.Instruction{
		Opcode:           "JMP",
		Suffixes:         nil,
		Operands:         []operand.Op{symbol(name)},
		Inputs:           nil,
		Outputs:          nil,
		IsTerminal:       true,
		IsBranch:         false,
		IsConditional:    false,
		CancellingInputs: false,
		ISA:              nil,
		Pred:             nil,
		Succ:             nil,
		LiveIn:           nil,
		LiveOut:          nil,
	})
}

// callMul returns a function that emits a call of fpMulAsm, with the
// arguments in args at the bottom of the frame. No register is live across
// the call, because each helper loads its pointers again.
func (g *generator) callMul(args operand.Mem) func(lhs, rhs, dst elem) {
	return func(lhs, rhs, dst elem) {
		for idx, arg := range []elem{dst, lhs, rhs} {
			ptr := g.GP64()

			if arg.param == "" {
				g.LEAQ(arg.slot, ptr)
			} else {
				g.Load(g.Param(arg.param), ptr)
				g.LEAQ(limb(ptr, arg.offset), ptr)
			}

			g.MOVQ(ptr, args.Offset(limbBytes*idx))
		}

		g.Instruction(&ir.Instruction{
			Opcode:           "CALL",
			Suffixes:         nil,
			Operands:         []operand.Op{symbol("fpMulAsm")},
			Inputs:           nil,
			Outputs:          nil,
			IsTerminal:       false,
			IsBranch:         false,
			IsConditional:    false,
			CancellingInputs: false,
			ISA:              nil,
			Pred:             nil,
			Succ:             nil,
			LiveIn:           nil,
			LiveOut:          nil,
		})
	}
}

// elem locates a field element: its limbs behind a pointer parameter, from
// limb offset on, or at a memory operand that needs no new register, such as
// a stack slot.
type elem struct {
	param  string      // the pointer parameter, or "" for a stack slot
	offset int         // the index of the first limb behind param
	slot   operand.Mem // the memory operand, if param is ""
}

func param(name string, offset int) elem {
	var slot operand.Mem

	return elem{param: name, offset: offset, slot: slot}
}

func stack(slot operand.Mem) elem { return elem{param: "", offset: 0, slot: slot} }

// newSlot returns a new stack slot for a field element.
func (g *generator) newSlot() elem { return stack(g.AllocLocal(limbBytes * g.limbs)) }

// limbsOf returns the memory operands of the limbs of element. For a
// parameter, it first loads the pointer into a new register.
func (g *generator) limbsOf(element elem) func(idx int) operand.Mem {
	if element.param == "" {
		return func(idx int) operand.Mem { return element.slot.Offset(limbBytes * idx) }
	}

	ptr := g.Load(g.Param(element.param), g.GP64())

	return func(idx int) operand.Mem { return limb(ptr, element.offset+idx) }
}

// fpMul emits fpMulAsm, which sets z = x·y/R mod p.
func (g *generator) fpMul() {
	g.begin("fpMulAsm", mulSignature, "fpMulAsm sets z = x·y/R mod p, where R = 2^(64·N).")
	g.montMul(param("x", 0), param("y", 0), param("z", 0))
	g.RET()
}

// fpSquare emits fpSquareAsm, which sets z = x²/R mod p, computing each cross
// product once: about N²/2 multiplications instead of N².
func (g *generator) fpSquare() {
	g.begin("fpSquareAsm", squareSignature, "fpSquareAsm sets z = x²/R mod p, where R = 2^(64·N).")
	g.squareProduct(param("x", 0), param("z", 0))
	g.RET()
}

// squareProduct emits code that sets dst = base²/R mod p for a reduced base
// in three phases, like the squaring of mike_c. It sums the cross products
// base_i·base_j, i < j, row by row into a 2N-limb product T; sets
// T = 2T + Σ base_k²·w^(2k), where w = 2^64; and then reduces T. Because the
// quotient limbs of the reduction are limbs of T, its multiplications don't
// depend on each other, unlike those of montMul.
//
// The low limbs of T up to squareStackLimbs go to the stack, and the others
// stay in registers.
func (g *generator) squareProduct(base, dst elem) {
	limbs := g.limbs
	product := g.AllocLocal(limbBytes * productLimbs * limbs)
	square := &squaring{
		limb:       make([]operand.Op, productLimbs*limbs),
		stack:      func(idx int) operand.Mem { return product.Offset(limbBytes * idx) },
		stackLimbs: g.squareStackLimbs(),
	}

	prodLo, prodHi := g.GP64(), g.GP64()
	xLimb := g.limbsOf(base)

	// The first row keeps N − 1 limbs of T in registers, besides RDX and the
	// product. If the pointer to base doesn't fit too, base is copied.
	if base.param != "" && limbs > rowRegs {
		copied := g.AllocLocal(limbBytes * limbs)

		for idx := range limbs {
			g.MOVQ(xLimb(idx), prodHi)
			g.MOVQ(prodHi, copied.Offset(limbBytes*idx))
		}

		xLimb = g.limbsOf(stack(copied))
	}

	g.squareCross(xLimb, square, prodLo, prodHi)
	g.squareDouble(base, square, prodLo, prodHi)
	g.squareReduce(square, dst, prodLo, prodHi)
}

// squaring holds the limbs of the product T of squareProduct: registers, or
// stack limbs for the indices below stackLimbs.
type squaring struct {
	limb       []operand.Op
	stack      func(idx int) operand.Mem
	stackLimbs int
}

// squareStackLimbs returns the number of low limbs of T that squareProduct
// keeps on the stack. Limb 0 is there in any case, because the reduction
// only reads it. The doubling phase needs RDX, the two halves of a square,
// and, if it updates limbs on the stack, a scratch register, besides the
// limbs of T in registers.
func (g *generator) squareStackLimbs() int {
	const doubleRegs = 3

	inRegs := productLimbs*g.limbs - 1
	if inRegs+doubleRegs <= allocatableRegs {
		return 1
	}

	return productLimbs*g.limbs - (allocatableRegs - doubleRegs - 1)
}

// squareCross emits the first phase of squareProduct: T = Σ_(i<j) x_i·x_j·
// w^(i+j). Row i adds x_i·(x_(i+1), …, x_(N−1)) at limbs 2i + 1 to i + N of T,
// which it keeps in registers. After row i, limbs 2i + 1 and 2i + 2 are
// final, and those below square.stackLimbs move to the stack.
func (g *generator) squareCross(xLimb func(idx int) operand.Mem, square *squaring, prodLo, prodHi reg.GPVirtual) {
	limbs := g.limbs
	pos := square.limb

	for row := range limbs - 1 {
		g.Commentf("Cross products with limb %d.", row)

		// New limbs of T start at zero; the XORs also clear CF and OF.
		top := row + limbs

		first := top
		if row == 0 {
			first = 2
		}

		for idx := first; idx <= top; idx++ {
			register := g.GP64()
			g.XORQ(register, register)
			pos[idx] = register
		}

		g.MOVQ(xLimb(row), reg.RDX)

		for col := row + 1; col < limbs; col++ {
			idx := row + col
			g.MULXQ(xLimb(col), prodLo, prodHi)

			if idx == 1 {
				// Limb 1 of T is this low half alone.
				pos[1] = square.stack(1)
				if square.stackLimbs == 1 {
					pos[1] = g.GP64()
				}

				g.MOVQ(prodLo, pos[1])
			} else {
				g.ADCXQ(prodLo, pos[idx])
			}

			g.ADOXQ(prodHi, pos[idx+1])
		}

		// The top limb was zero, so the OF chain ended without a carry.
		g.ADCQ(operand.U8(0), pos[top])

		for _, idx := range []int{2*row + 1, 2*row + 2} {
			if register, ok := pos[idx].(reg.GPVirtual); ok && idx < square.stackLimbs {
				g.MOVQ(register, square.stack(idx))
				pos[idx] = square.stack(idx)
			}
		}
	}
}

// squareDouble emits the second phase of squareProduct: T = 2T + Σ x_k²·w^(2k),
// with the doubling in the CF chain and the squares in the OF chain. Limbs 0
// and 2N − 1 of T start at zero.
func (g *generator) squareDouble(base elem, square *squaring, sqLo, sqHi reg.GPVirtual) {
	limbs := g.limbs
	pos := square.limb

	var scratch reg.GPVirtual
	if square.stackLimbs > 1 {
		scratch = g.GP64()
	}

	g.Comment("Double the cross products and add the squares.")
	g.XORQ(sqHi, sqHi) // clears CF and OF

	for idx := range limbs {
		g.loadMultiplier(base, idx)
		g.MULXQ(reg.RDX, sqLo, sqHi)

		for half, value := range []reg.GPVirtual{sqLo, sqHi} {
			limb := productLimbs*idx + half

			switch {
			case limb == 0:
				// No carries are pending yet, so limb 0 is the low half.
				pos[0] = square.stack(0)
				g.MOVQ(value, pos[0])
			case limb == productLimbs*limbs-1:
				// MOV leaves the flags alone.
				register := g.GP64()
				g.MOVQ(operand.U32(0), register)
				g.ADCXQ(register, register)
				g.ADOXQ(value, register)
				pos[limb] = register
			case operand.IsMem(pos[limb]):
				g.MOVQ(pos[limb], scratch)
				g.ADCXQ(scratch, scratch)
				g.ADOXQ(value, scratch)
				g.MOVQ(scratch, pos[limb])
			default:
				g.ADCXQ(pos[limb], pos[limb])
				g.ADOXQ(value, pos[limb])
			}
		}
	}
}

// squareReduce emits the third phase of squareProduct: it stores into dst the
// high N limbs of T + top·M·w^(N−1), reduced below p, where the quotient M has
// the limbs m_i = T[i] for i < N − 1 and m_(N−1) = T[N−1] + lo(m_0·top). Then
// the low N limbs of T + top·M·w^(N−1) − M are zero, as in emitSquareReduce
// in internal/gen, so the high limbs are the Montgomery reduction of T.
func (g *generator) squareReduce(square *squaring, dst elem, prodLo, prodHi reg.GPVirtual) {
	limbs := g.limbs
	pos := square.limb
	acc := slices.Clone(pos[limbs:])

	g.Comment("Reduce the product.")

	// Load the high limbs on the stack while registers are free.
	for idx, limb := range acc {
		if operand.IsMem(limb) && idx < rowRegs {
			register := g.GP64()
			g.MOVQ(limb, register)
			acc[idx] = register
		}
	}

	g.MOVQ(operand.U64(g.top), reg.RDX)
	g.XORQ(prodLo, prodLo) // clears CF and OF

	for idx := range limbs {
		g.MULXQ(pos[idx], prodLo, prodHi)

		if idx == 0 {
			// m_(N−1) = T[N−1] + lo(m_0·top), and its carry enters the CF chain.
			g.addCarry(g.ADCXQ, prodLo, pos[limbs-1])
		} else {
			g.addCarry(g.ADCXQ, prodLo, acc[idx-1])
		}

		g.addCarry(g.ADOXQ, prodHi, acc[idx])
	}

	g.ADCQ(operand.U8(0), acc[limbs-1])
	g.storeReduced(acc, dst)
}

// fp2Mul emits fp2MulAsm, which sets z = x·y in GF(p²) with three
// multiplications: for x = a + i·b and y = c + i·d, ac − bd and
// (a + b)(c + d) − ac − bd. The sums are not reduced, which montMul allows.
// The frame can be large, so the function may grow the stack. Above
// maxFp2Limbs, it calls fpMulAsm for the products.
func (g *generator) fp2Mul() {
	g.Function("fp2MulAsm")
	g.SignatureExpr(fmt.Sprintf(fp2MulSignature, g.limbs))

	g.Doc("fp2MulAsm sets z = x·y in GF(p²), with the components in Montgomery form.",
		"The inputs must be reduced, and z may alias them.")

	limbs := g.limbs
	mul := g.montMul

	if limbs > maxFp2Limbs {
		mul = g.callMul(g.AllocLocal(limbBytes * mulArgs))
	}

	sumX, sumY, prodRe, prodIm, prodSum := g.newSlot(), g.newSlot(), g.newSlot(), g.newSlot(), g.newSlot()

	g.addLimbs(sumX, param("x", 0), param("x", limbs))
	g.addLimbs(sumY, param("y", 0), param("y", limbs))
	mul(param("x", 0), param("y", 0), prodRe)
	mul(param("x", limbs), param("y", limbs), prodIm)
	mul(sumX, sumY, prodSum)
	g.subMod(param("z", 0), prodRe, prodIm)
	g.subMod(param("z", limbs), prodSum, prodRe)
	g.subMod(param("z", limbs), param("z", limbs), prodIm)
	g.RET()
}

// fp2Square emits fp2SquareAsm, which sets z = x² in GF(p²) with two
// multiplications: for x = a + i·b, (a + b)(a − b + p) and (2a)·b. The
// factors are not reduced, which montMul allows. Above maxFp2Limbs, it calls
// fpMulAsm for the products.
func (g *generator) fp2Square() {
	g.Function("fp2SquareAsm")
	g.SignatureExpr(fmt.Sprintf(fp2SquareSignature, g.limbs))

	g.Doc("fp2SquareAsm sets z = x² in GF(p²), with the components in Montgomery form.",
		"The input must be reduced, and z may alias it.")

	limbs := g.limbs
	mul := g.montMul

	if limbs > maxFp2Limbs {
		mul = g.callMul(g.AllocLocal(limbBytes * mulArgs))
	}

	sum, diff, double := g.newSlot(), g.newSlot(), g.newSlot()

	g.addLimbs(sum, param("x", 0), param("x", limbs))
	g.subFromModulus(diff, param("x", limbs))
	g.addLimbs(diff, param("x", 0), diff)
	g.addLimbs(double, param("x", 0), param("x", 0))

	// Writing z.re first is safe even if z aliases x: x.re is no longer
	// needed, and z.re doesn't overlap x.im.
	mul(sum, diff, param("z", 0))
	mul(double, param("x", limbs), param("z", limbs))
	g.RET()
}

// hadamard emits theta4HadamardAsm, which applies the Hadamard transform to
// the 16 coordinates of a theta point in place: four layers of butterflies
// (a, b) → (a + b, a − b) mod p. Each layer reads one buffer and writes the
// other, alternating between the point and a copy on the stack, so that a
// butterfly can write its sum before it reads its inputs again. The fourth
// layer writes back into the point.
func (g *generator) hadamard() {
	g.Function("theta4HadamardAsm")
	g.SignatureExpr(fmt.Sprintf(hadamardSignature, g.limbs))
	g.Doc("theta4HadamardAsm applies the Hadamard transform to the theta point p in place.",
		"The coordinates must be reduced.")

	limbs := g.limbs
	local := g.AllocLocal(limbBytes * thetaCoords * limbs)
	buffers := [2]func(coord int) elem{
		func(coord int) elem { return param("p", coord*limbs) },
		func(coord int) elem { return stack(local.Offset(limbBytes * coord * limbs)) },
	}

	// If a register is left, the pointer to p stays in it. Otherwise, each
	// butterfly loads it again where it needs it.
	if limbs <= maxPointerLimbs {
		ptr := g.Load(g.Param("p"), g.GP64())
		buffers[0] = func(coord int) elem { return stack(limb(ptr, coord*limbs)) }
	}

	for layer := range 4 {
		stride := 1 << layer
		src, dst := buffers[layer%2], buffers[(layer+1)%2]

		for coord := range thetaCoords {
			if coord&stride != 0 {
				continue
			}

			g.Commentf("Layer %d, coordinates %d and %d.", layer, coord, coord+stride)
			g.addMod(dst(coord), src(coord), src(coord+stride))
			g.subMod(dst(coord+stride), src(coord), src(coord+stride))
		}
	}

	g.RET()
}

// addMod emits dst = a + b mod p, for reduced a and b, computing the sum in
// registers: it subtracts p and adds p back if that borrowed. dst may be a or
// b.
func (g *generator) addMod(dst, a, b elem) {
	aLimb, bLimb := g.limbsOf(a), g.limbsOf(b)
	sum := g.newLimbRegs()

	for idx, limbReg := range sum {
		g.MOVQ(aLimb(idx), limbReg)

		if idx == 0 {
			g.ADDQ(bLimb(idx), limbReg)
		} else {
			g.ADCQ(bLimb(idx), limbReg)
		}
	}

	top := g.GP64()
	g.MOVQ(operand.U64(g.top-1), top)

	for idx, limbReg := range sum {
		src := operand.Op(operand.I32(-1))
		if idx == g.limbs-1 {
			src = top
		}

		if idx == 0 {
			g.SUBQ(src, limbReg)
		} else {
			g.SBBQ(src, limbReg)
		}
	}

	g.addBackModulus(sum, top)
	g.storeLimbs(dst, sum)
}

// subMod emits dst = a − b mod p, for reduced a and b, computing the
// difference in registers: it adds p back if the subtraction borrowed. dst may
// be a or b.
func (g *generator) subMod(dst, a, b elem) {
	aLimb, bLimb := g.limbsOf(a), g.limbsOf(b)
	diff := g.newLimbRegs()

	for idx, limbReg := range diff {
		g.MOVQ(aLimb(idx), limbReg)

		if idx == 0 {
			g.SUBQ(bLimb(idx), limbReg)
		} else {
			g.SBBQ(bLimb(idx), limbReg)
		}
	}

	top := g.GP64()
	g.MOVQ(operand.U64(g.top-1), top)
	g.addBackModulus(diff, top)
	g.storeLimbs(dst, diff)
}

// newLimbRegs returns N new registers for the limbs of an element.
func (g *generator) newLimbRegs() []reg.GPVirtual {
	regs := make([]reg.GPVirtual, g.limbs)
	for idx := range regs {
		regs[idx] = g.GP64()
	}

	return regs
}

// addBackModulus emits code that adds p to the limbs in regs if the
// preceding subtraction borrowed. top must hold the top limb of p, top − 1;
// it is overwritten.
func (g *generator) addBackModulus(regs []reg.GPVirtual, top reg.GPVirtual) {
	// mask = −borrow. The low limbs of p are all ones, so p AND mask is
	// mask in them.
	mask := g.GP64()
	g.SBBQ(mask, mask)
	g.ANDQ(mask, top)

	for idx, limbReg := range regs {
		src := operand.Op(mask)
		if idx == g.limbs-1 {
			src = top
		}

		if idx == 0 {
			g.ADDQ(src, limbReg)
		} else {
			g.ADCQ(src, limbReg)
		}
	}
}

// storeLimbs emits code that stores the limbs in regs into dst.
func (g *generator) storeLimbs(dst elem, regs []reg.GPVirtual) {
	dstLimb := g.limbsOf(dst)
	for idx, limbReg := range regs {
		g.MOVQ(limbReg, dstLimb(idx))
	}
}

// montMul emits code that sets dst = lhs·rhs/R mod p, reduced, by operand
// scanning. lhs and rhs must be below 2p: then the accumulator stays below 3p
// between rows and the result below 2p, because every prime has 4p < R.
//
// Each row adds lhs·rhs_i to the N + 1 accumulator limbs with MULX in two carry
// chains, ADCX for the low halves of the products and ADOX for the high
// halves. It then adds q·top and drops the low limb.
//
// When the registers run out, an lhs behind a pointer is copied to the stack,
// where the instructions address it through SP, and then the accumulator
// limbs beyond the remaining registers live on the stack too.
func (g *generator) montMul(lhs, rhs, dst elem) {
	limbs := g.limbs
	xOnStack := lhs.param != "" && limbs+1 > rowRegs-1

	ptrRegs := 0
	if lhs.param != "" && !xOnStack {
		ptrRegs = 1
	}

	inRegs := min(limbs+1, rowRegs-ptrRegs)

	stackLimbs := limbs + 1 - inRegs
	if xOnStack {
		stackLimbs += limbs
	}

	var local operand.Mem
	if stackLimbs > 0 {
		local = g.AllocLocal(limbBytes * stackLimbs)
	}

	prodLo, prodHi := g.GP64(), g.GP64()
	xLimb := g.limbsOf(lhs)

	if xOnStack {
		for idx := range limbs {
			g.MOVQ(xLimb(idx), prodHi)
			g.MOVQ(prodHi, local.Offset(limbBytes*idx))
		}

		xLimb = g.limbsOf(stack(local))
	}

	acc := g.newAccumulator(local, stackLimbs, inRegs)

	// The XORs that zeroed the registers cleared CF and OF.
	for row := range limbs {
		g.Commentf("Row %d.", row)
		g.loadMultiplier(rhs, row)

		for idx := range limbs {
			g.MULXQ(xLimb(idx), prodLo, prodHi)
			g.addCarry(g.ADCXQ, prodLo, acc[idx])
			g.addCarry(g.ADOXQ, prodHi, acc[idx+1])
		}

		// The top limb was zero, so the OF chain ended without a carry, and
		// ADC can take the last carry of the CF chain.
		g.ADCQ(operand.U8(0), acc[limbs])

		g.MOVQ(operand.U64(g.top), reg.RDX)
		g.MULXQ(acc[0], prodLo, prodHi)
		g.ADDQ(prodLo, acc[limbs-1])
		g.ADCQ(prodHi, acc[limbs])

		acc = g.shiftDown(acc, inRegs, prodLo)
	}

	g.storeReduced(acc[:limbs], dst)
}

// loadMultiplier emits code that loads limb row of rhs into RDX, the implicit
// operand of MULX. A pointer parameter is loaded into RDX first, so that it
// takes no other register.
func (g *generator) loadMultiplier(rhs elem, row int) {
	if rhs.param == "" {
		g.MOVQ(rhs.slot.Offset(limbBytes*row), reg.RDX)

		return
	}

	g.Load(g.Param(rhs.param), reg.RDX)
	g.MOVQ(limb(reg.RDX, rhs.offset+row), reg.RDX)
}

// addLimbs emits dst = a + b without reduction. The sum must fit in N limbs.
func (g *generator) addLimbs(dst, a, b elem) {
	dstLimb, aLimb, bLimb := g.limbsOf(dst), g.limbsOf(a), g.limbsOf(b)
	scratch := g.GP64()

	for idx := range g.limbs {
		g.MOVQ(aLimb(idx), scratch)

		if idx == 0 {
			g.ADDQ(bLimb(idx), scratch)
		} else {
			g.ADCQ(bLimb(idx), scratch)
		}

		g.MOVQ(scratch, dstLimb(idx))
	}
}

// subFromModulus emits dst = p − b, for b ≤ p.
func (g *generator) subFromModulus(dst, b elem) {
	dstLimb, bLimb := g.limbsOf(dst), g.limbsOf(b)
	scratch := g.GP64()

	for idx := range g.limbs {
		g.MOVQ(operand.U64(g.modulusLimb(idx)), scratch)

		if idx == 0 {
			g.SUBQ(bLimb(idx), scratch)
		} else {
			g.SBBQ(bLimb(idx), scratch)
		}

		g.MOVQ(scratch, dstLimb(idx))
	}
}

// modulusLimb returns limb idx of p.
func (g *generator) modulusLimb(idx int) uint64 {
	if idx < g.limbs-1 {
		return math.MaxUint64
	}

	return g.top - 1
}

// newAccumulator returns N + 1 zero limbs: the first inRegs in registers,
// and the others at the end of local, which has stackLimbs limbs.
func (g *generator) newAccumulator(local operand.Mem, stackLimbs, inRegs int) []operand.Op {
	acc := make([]operand.Op, g.limbs+1)

	for idx := range acc {
		if idx < inRegs {
			register := g.GP64()
			g.XORQ(register, register)
			acc[idx] = register

			continue
		}

		acc[idx] = local.Offset(limbBytes * (stackLimbs - len(acc) + idx))
		g.MOVQ(operand.U32(0), acc[idx])
	}

	return acc
}

// shiftDown drops the low limb of acc and returns the accumulator for the
// next row. The register of the dropped limb takes the lowest stack limb, if
// any, and the limb that becomes free is the new top limb, zero. Zeroing it
// also clears CF and OF for the next row, with scratch if the top limb is on
// the stack.
func (g *generator) shiftDown(acc []operand.Op, inRegs int, scratch reg.GPVirtual) []operand.Op {
	free := acc[0]
	if inRegs < len(acc) {
		g.MOVQ(acc[inRegs], free)
		free, acc[inRegs] = acc[inRegs], free
	}

	acc = append(acc[1:], free)

	if top := acc[len(acc)-1]; operand.IsMem(top) {
		g.MOVQ(operand.U32(0), top)
		g.XORQ(scratch, scratch)
	} else {
		g.XORQ(top, top)
	}

	return acc
}

// addCarry adds src and a carry flag to dst with add, which is ADCX or ADOX
// and needs a register destination. For a dst on the stack, it adds into src
// and stores the sum.
func (g *generator) addCarry(add func(mr, r operand.Op), src reg.GPVirtual, dst operand.Op) {
	if operand.IsMem(dst) {
		add(dst, src)
		g.MOVQ(src, dst)

		return
	}

	add(src, dst)
}

// storeReduced stores value, below 2p in registers or stack limbs, into dst,
// after subtracting p if value ≥ p. It selects the result with CMOV, so it
// runs in constant time.
func (g *generator) storeReduced(value []operand.Op, dst elem) {
	dstLimb := g.limbsOf(dst)

	// With registers to spare, subtract p from a copy of value in registers.
	if 2*len(value)+2 <= allocatableRegs && !slices.ContainsFunc(value, operand.IsMem) {
		diff := make([]operand.Op, len(value))

		for idx, src := range value {
			register := g.GP64()
			g.MOVQ(src, register)
			diff[idx] = register
		}

		g.subtractModulus(diff)

		// The subtraction didn't borrow if value ≥ p. Then dst gets the
		// difference.
		for idx, src := range value {
			g.CMOVQCC(diff[idx], src)
			g.MOVQ(src, dstLimb(idx))
		}

		return
	}

	scratch := g.GP64()

	for idx, src := range value {
		g.MOVQ(src, scratch)
		g.MOVQ(scratch, dstLimb(idx))
	}

	// Subtract p from value in place. It borrowed if value < p. Then dst
	// keeps value.
	g.subtractModulus(value)

	for idx, src := range value {
		g.MOVQ(src, scratch)
		g.CMOVQCS(dstLimb(idx), scratch)
		g.MOVQ(scratch, dstLimb(idx))
	}
}

// subtractModulus emits value −= p, leaving the borrow in CF.
func (g *generator) subtractModulus(value []operand.Op) {
	// The low limbs of p are all ones.
	pTop := g.GP64()
	g.MOVQ(operand.U64(g.top-1), pTop)

	for idx, limbOp := range value {
		switch {
		case idx == 0:
			g.SUBQ(operand.I32(-1), limbOp)
		case idx < len(value)-1:
			g.SBBQ(operand.I32(-1), limbOp)
		default:
			g.SBBQ(pTop, limbOp)
		}
	}
}

// symbol returns the memory operand of the package symbol name.
func symbol(name string) operand.Mem {
	return operand.NewDataAddr(operand.Symbol{Name: "·" + name, Static: false}, 0)
}

// limb returns the memory operand of limb idx of the element at ptr.
func limb(ptr reg.Register, idx int) operand.Mem {
	return operand.Mem{
		Symbol: operand.Symbol{Name: "", Static: false},
		Disp:   limbBytes * idx,
		Base:   ptr,
		Index:  nil,
		Scale:  0,
	}
}
