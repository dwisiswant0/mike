// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package p308

import "testing"

// testDoublings is the number of doublings the tests compare between
// doubling methods.
const testDoublings = 7

// randomPrivateKey returns a random valid private key.
func randomPrivateKey(rnd *testRand) []byte {
	priv := rnd.bytes(PrivateKeySize)
	ClampPrivateKey(priv)

	return priv
}

// testCurve returns a random supersingular curve: a public key.
func testCurve(t *testing.T, rnd *testRand) curve {
	t.Helper()

	ell, err := decodePublicKey(PublicKey(randomPrivateKey(rnd)))
	if err != nil {
		t.Fatal(err)
	}

	return ell
}

// randPoint returns a random point on ell.
func randPoint(t *testing.T, ell *curve, rnd *testRand) point {
	t.Helper()

	for {
		coordX := toFp2(t, randGf2(rnd))

		var coordY, one fp2

		coordY.add(&coordX, &ell.a).mul(&coordY, &coordX).add(&coordY, one.one()).mul(&coordY, &coordX)

		if coordY.sqrt(&coordY) == 1 {
			var res point

			res.x, res.y = coordX, coordY
			res.z.one()

			return res
		}
	}
}

// samePoint reports whether lhs and rhs are the same point.
func samePoint(lhs, rhs *point) bool {
	if lhs.isInfinity() == 1 || rhs.isInfinity() == 1 {
		return lhs.isInfinity() == rhs.isInfinity()
	}

	// (X : Y : Z) has x = X/Z² and y = Y/Z³.
	var lhsZ, rhsZ, lhsProd, rhsProd fp2

	lhsZ.square(&lhs.z)
	rhsZ.square(&rhs.z)

	if lhsProd.mul(&lhs.x, &rhsZ).equal(rhsProd.mul(&rhs.x, &lhsZ)) != 1 {
		return false
	}

	lhsZ.mul(&lhsZ, &lhs.z)
	rhsZ.mul(&rhsZ, &rhs.z)

	return lhsProd.mul(&lhs.y, &rhsZ).equal(rhsProd.mul(&rhs.y, &lhsZ)) == 1
}

// sameX reports whether lhs and rhs have the same x-coordinate.
func sameX(lhs, rhs *pointX) bool {
	var lhsProd, rhsProd fp2

	return lhsProd.mul(&lhs.x, &rhs.z).equal(rhsProd.mul(&rhs.x, &lhs.z)) == 1
}

func TestCurveGroupLaw(t *testing.T) {
	t.Parallel()

	rnd := newTestRand(t.Name())
	ell := testCurve(t, rnd)

	var inf point

	inf.setInfinity()

	for range 20 {
		ptP, ptQ, ptS := randPoint(t, &ell, rnd), randPoint(t, &ell, rnd), randPoint(t, &ell, rnd)

		sumPQ, sumQP := ell.add(&ptP, &ptQ), ell.add(&ptQ, &ptP)
		if !samePoint(&sumPQ, &sumQP) {
			t.Fatal("P + Q ≠ Q + P")
		}

		sumQS := ell.add(&ptQ, &ptS)

		lhs, rhs := ell.add(&sumPQ, &ptS), ell.add(&ptP, &sumQS)
		if !samePoint(&lhs, &rhs) {
			t.Fatal("(P + Q) + S ≠ P + (Q + S)")
		}

		sumPP, dblP := ell.add(&ptP, &ptP), ell.double(&ptP)
		if !samePoint(&sumPP, &dblP) {
			t.Fatal("P + P ≠ [2]P")
		}

		if res := ell.sub(&ptP, &ptP); res.isInfinity() != 1 {
			t.Fatal("P − P ≠ ∞")
		}

		if res := ell.add(&ptP, &inf); !samePoint(&res, &ptP) {
			t.Fatal("P + ∞ ≠ P")
		}

		if res := ell.add(&inf, &ptP); !samePoint(&res, &ptP) {
			t.Fatal("∞ + P ≠ P")
		}
	}
}

func TestCurveDoublingAndX(t *testing.T) {
	t.Parallel()

	rnd := newTestRand(t.Name())
	ell := testCurve(t, rnd)

	var aDiv3 fp2

	aDiv3.setUint64(weierstrassShiftDen).invert(&aDiv3).mul(&aDiv3, &ell.a)

	for range 20 {
		ptP, ptQ := randPoint(t, &ell, rnd), randPoint(t, &ell, rnd)

		slow, fast := ell.doubleN(&ptP, testDoublings), ell.doubleNFast(&ptP, &aDiv3, testDoublings)
		if !samePoint(&slow, &fast) {
			t.Fatal("doubleNFast ≠ doubleN")
		}

		dbl := ell.double(&ptP)
		xP, dblX := ptP.toX(), dbl.toX()
		ell.xdbl(&xP)

		if !sameX(&xP, &dblX) {
			t.Fatal("xdbl ≠ double")
		}

		// x(P ± Q) = (u ∓ v)/w.
		compU, compV, compW := ell.addComponents(&ptP, &ptQ)
		sum, diff := ell.add(&ptP, &ptQ), ell.sub(&ptP, &ptQ)

		var plus, minus pointX

		plus.x.sub(&compU, &compV)
		minus.x.add(&compU, &compV)
		plus.z, minus.z = compW, compW

		if sumX, diffX := sum.toX(), diff.toX(); !sameX(&plus, &sumX) || !sameX(&minus, &diffX) {
			t.Fatal("addComponents is wrong")
		}
	}
}

func TestCurveMul(t *testing.T) {
	t.Parallel()

	rnd := newTestRand(t.Name())
	ell := testCurve(t, rnd)
	ptP := randPoint(t, &ell, rnd)

	var acc point // [n]P

	acc.setInfinity()

	for scalar := range byte(70) {
		// Short and long scalars, with and without skipping the lowest bit.
		for _, nbits := range []int{8, 30} {
			if got := ell.mul(&ptP, []byte{scalar, 0, 0, 0}, 0, nbits); !samePoint(&got, &acc) {
				t.Fatalf("[%d]P with %d bits is wrong", scalar, nbits)
			}

			odd := scalar<<1 | 1
			if got := ell.mul(&ptP, []byte{odd, 0, 0, 0}, 1, nbits); !samePoint(&got, &acc) {
				t.Fatalf("[(%d − 1)/2]P with %d bits is wrong", odd, nbits)
			}
		}

		xP := ptP.toX()
		if got, want := ell.xmul(&xP, uint64(scalar)), acc.toX(); scalar > 0 && !sameX(&got, &want) {
			t.Fatalf("x([%d]P) is wrong", scalar)
		}

		acc = ell.add(&acc, &ptP)
	}
}

func TestThreePointLadder(t *testing.T) {
	t.Parallel()

	rnd := newTestRand(t.Name())
	ell := testCurve(t, rnd)

	// The three-point ladder computes x(P + [n]Q).
	ptP, ptQ := randPoint(t, &ell, rnd), randPoint(t, &ell, rnd)
	diff := ell.sub(&ptP, &ptQ)
	basis := basisX{p: ptP.toX(), q: ptQ.toX(), pq: diff.toX()}
	want := ptP

	for scalar := range byte(40) {
		got := ell.threePointLadder(&basis, []byte{scalar}, byteBits)
		if wantX := want.toX(); !sameX(&got, &wantX) {
			t.Fatalf("x(P + [%d]Q) is wrong", scalar)
		}

		want = ell.add(&want, &ptQ)
	}
}

func TestTorsionBasis(t *testing.T) {
	t.Parallel()

	rnd := newTestRand(t.Name())
	ell := testCurve(t, rnd)

	basis, ok := ell.torsionBasis(primeExponent-basisOrderLog, primeCofactor)
	if !ok {
		t.Fatal("torsionBasis failed")
	}

	ptP, ptQ := ell.liftBasis(&basis)

	// P and Q have order exactly 2^n, and [2^(n−1)]Q = (0, 0).
	for _, pt := range []point{ptP, ptQ} {
		half := ell.doubleN(&pt, basisOrderLog-1)
		if half.isInfinity() == 1 || half.y.isZero() != 1 {
			t.Fatal("order below 2^n")
		}

		if res := ell.double(&half); res.isInfinity() != 1 {
			t.Fatal("order above 2^n")
		}
	}

	halfP, halfQ := ell.doubleN(&ptP, basisOrderLog-1), ell.doubleN(&ptQ, basisOrderLog-1)
	if halfQ.x.isZero() != 1 {
		t.Fatal("[2^(n−1)]Q ≠ (0, 0)")
	}

	if samePoint(&halfP, &halfQ) {
		t.Fatal("P and Q are dependent")
	}
	// The lift agrees with x(P − Q).
	diff := ell.sub(&ptP, &ptQ)
	if diffX := diff.toX(); !sameX(&diffX, &basis.pq) {
		t.Fatal("x(P − Q) does not match the basis")
	}
}
