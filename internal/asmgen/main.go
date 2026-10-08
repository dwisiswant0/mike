// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

// Command asmgen generates fp_amd64.s, the amd64 assembly of the field
// multiplication and squaring, for each prime in internal/gen/params.txt.
// Run it with "go generate" in the module root.
//
// It is a module of its own, so that the mike module doesn't depend on avo.
package main

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
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

	// rowRegs is the number of registers that mulRows has for the
	// accumulator limbs and the pointer to x: the 14 allocatable registers,
	// less RDX and the two halves of a product.
	rowRegs = 11

	// colSquareLimbs is the smallest number of limbs for which fpSquare
	// squares by columns instead of multiplying x by itself. Squaring by
	// columns computes about half as many limb products, but in longer
	// dependency chains. On an AMD EPYC 7763, it was faster from 10 limbs.
	colSquareLimbs = 10

	// The signatures of the functions, given the number of limbs.
	mulSignature    = "func(z, x, y *[%d]uint64)"
	squareSignature = "func(z, x *[%d]uint64)"

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
	gen.dispatch("fpMul", mulSignature)
	gen.dispatch("fpSquare", squareSignature)
	gen.mulRows("fpMulAsm", mulSignature, "y")

	if fld.limbs < colSquareLimbs {
		gen.mulRows("fpSquareAsm", squareSignature, "x")
	} else {
		gen.squareColumns()
	}

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

// mulRows emits name, which sets z = x·y/R mod p by operand scanning, where
// y is the parameter yParam. Each row adds x·y_i to the N + 1 accumulator
// limbs with MULX in two carry chains, ADCX for the low halves of the
// products and ADOX for the high halves. It then adds q·top and drops the
// low limb.
//
// When the registers run out, x is copied to the stack, where the
// instructions address it through SP, and then the accumulator limbs beyond
// the remaining registers live on the stack too.
func (g *generator) mulRows(name, signature, yParam string) {
	g.begin(name, signature, fmt.Sprintf("%s sets z = x·%s/R mod p, where R = 2^(64·N).", name, yParam))

	limbs := g.limbs
	xOnStack := limbs+1 > rowRegs-1
	inRegs := min(limbs+1, rowRegs)

	stackLimbs := limbs + 1 - inRegs
	if xOnStack {
		stackLimbs += limbs
	}

	var local operand.Mem
	if stackLimbs > 0 {
		local = g.AllocLocal(limbBytes * stackLimbs)
	}

	prodLo, prodHi := g.GP64(), g.GP64()
	xLimb := g.loadX(local, xOnStack, prodHi)
	acc := g.newAccumulator(local, stackLimbs, inRegs)

	// The XORs that zeroed the registers cleared CF and OF.
	for row := range limbs {
		g.Commentf("Row %d.", row)
		g.Load(g.Param(yParam), reg.RDX)
		g.MOVQ(limb(reg.RDX, row), reg.RDX)

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

	g.storeReduced(acc[:limbs])
}

// loadX returns the memory operands of the limbs of x: behind the pointer in
// a register, or, if onStack, in a copy at the start of local, which it makes
// with the scratch register.
func (g *generator) loadX(local operand.Mem, onStack bool, scratch reg.GPVirtual) func(idx int) operand.Mem {
	ptr := g.Load(g.Param("x"), g.GP64())

	if !onStack {
		return func(idx int) operand.Mem { return limb(ptr, idx) }
	}

	for idx := range g.limbs {
		g.MOVQ(limb(ptr, idx), scratch)
		g.MOVQ(scratch, local.Offset(limbBytes*idx))
	}

	return func(idx int) operand.Mem { return local.Offset(limbBytes * idx) }
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

// squareColumns emits fpSquareAsm, which sets z = x²/R mod p by product
// scanning. Column k of the square sums the limb products of weight 2^(64k)
// in a three-limb accumulator. The quotient limb q_k that clears column
// k < N is reduced in column k + N − 1.
func (g *generator) squareColumns() {
	g.begin("fpSquareAsm", squareSignature, "fpSquareAsm sets z = x²/R mod p, where R = 2^(64·N).")

	limbs := g.limbs
	local := g.AllocLocal(limbBytes * limbs) // the quotient limbs, then the result
	slot := func(idx int) operand.Mem { return local.Offset(limbBytes * idx) }

	acc := [3]reg.GPVirtual{g.GP64(), g.GP64(), g.GP64()}
	cross := [3]reg.GPVirtual{g.GP64(), g.GP64(), g.GP64()}
	g.zero(acc[:]...)

	top := g.GP64()
	g.MOVQ(operand.U64(g.top), top)

	xPtr := g.Load(g.Param("x"), g.GP64())

	for col := range 2*limbs - 1 {
		g.Commentf("Column %d.", col)
		g.addSquareColumn(acc, cross, xPtr, col)

		if col >= limbs-1 {
			g.MOVQ(slot(col-limbs+1), reg.RAX)
			g.MULQ(top)
			g.addProduct(acc)
		}

		// For col < N, the low limb is q_col. For col ≥ N, it is limb
		// col − N of the result, and q_(col−N), which the slot held, is no
		// longer needed.
		g.MOVQ(acc[0], slot(col%limbs))

		acc = [3]reg.GPVirtual{acc[1], acc[2], acc[0]}
		g.zero(acc[2])
	}

	g.MOVQ(acc[0], slot(limbs-1))

	result := make([]operand.Op, limbs)
	for idx := range result {
		result[idx] = slot(idx)
	}

	g.storeReduced(result)
}

// addSquareColumn adds the limb products of column col of x² to acc. It sums
// each cross product x_i·x_j, i < j, once, in cross, and adds cross twice.
func (g *generator) addSquareColumn(acc, cross [3]reg.GPVirtual, xPtr reg.Register, col int) {
	first := max(0, col-g.limbs+1)

	hasCross := first < col-first
	if hasCross {
		g.zero(cross[:]...)
	}

	for idx := first; idx <= col-idx; idx++ {
		g.MOVQ(limb(xPtr, idx), reg.RAX)

		if idx == col-idx {
			g.MULQ(reg.RAX)
			g.addProduct(acc)
		} else {
			g.MULQ(limb(xPtr, col-idx))
			g.addProduct(cross)
		}
	}

	if hasCross {
		g.add(acc, cross)
		g.add(acc, cross)
	}
}

// addProduct adds the product in RDX:RAX to acc.
func (g *generator) addProduct(acc [3]reg.GPVirtual) {
	g.ADDQ(reg.RAX, acc[0])
	g.ADCQ(reg.RDX, acc[1])
	g.ADCQ(operand.U8(0), acc[2])
}

// add adds src to acc.
func (g *generator) add(acc, src [3]reg.GPVirtual) {
	g.ADDQ(src[0], acc[0])
	g.ADCQ(src[1], acc[1])
	g.ADCQ(src[2], acc[2])
}

// storeReduced stores value, below 2p in registers or stack limbs, into z,
// after subtracting p if value ≥ p, and returns. It subtracts p in place and
// selects the result with CMOV, so it runs in constant time.
func (g *generator) storeReduced(value []operand.Op) {
	zPtr := g.Load(g.Param("z"), g.GP64())
	scratch := g.GP64()

	for idx, src := range value {
		g.MOVQ(src, scratch)
		g.MOVQ(scratch, limb(zPtr, idx))
	}

	// The low limbs of p are all ones.
	pTop := g.GP64()
	g.MOVQ(operand.U64(g.top-1), pTop)

	for idx, dst := range value {
		switch {
		case idx == 0:
			g.SUBQ(operand.I32(-1), dst)
		case idx < len(value)-1:
			g.SBBQ(operand.I32(-1), dst)
		default:
			g.SBBQ(pTop, dst)
		}
	}

	// The subtraction borrowed if value < p. Then z keeps value.
	for idx, src := range value {
		g.MOVQ(src, scratch)
		g.CMOVQCS(limb(zPtr, idx), scratch)
		g.MOVQ(scratch, limb(zPtr, idx))
	}

	g.RET()
}

func (g *generator) zero(registers ...reg.GPVirtual) {
	for _, register := range registers {
		g.XORQ(register, register)
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
