// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"
)

// The costs of the steps of the 4-isogeny chain of key generation, in
// multiplications in GF(p): a multiplication in GF(p²) costs three, and a
// squaring two.
const (
	fp2MulCost    = 3
	fp2SquareCost = 2

	// quadrupleCost is the cost of multiplying a point by 4: two doublings,
	// each with four multiplications and two squarings.
	quadrupleCost = 2 * (4*fp2MulCost + 2*fp2SquareCost)

	// fourIsogenyEvalCost is the cost of evaluating a 4-isogeny at a point:
	// six multiplications and two squarings.
	fourIsogenyEvalCost = 6*fp2MulCost + 2*fp2SquareCost

	// splitsPerLine is the number of entries per line of the tables of
	// splits.
	splitsPerLine = 16

	// fourIsogenyDegreeLog is log₂ of the degree of a step of the chain.
	fourIsogenyDegreeLog = 2
)

// The costs of the steps of the theta chain of the shared secret, for a stack
// entry of two theta points with 16 coordinates, in tenths of a
// multiplication in GF(p): a squaring costs about 0.7 multiplications, and a
// Hadamard transform about 6.
const (
	thetaMulCost    = 10 * 16
	thetaSquareCost = 7 * 16
	hadamardCost    = 60

	// thetaDoubleCost is the cost of doubling both points of an entry.
	thetaDoubleCost = 2 * (2*thetaSquareCost + 2*thetaMulCost + 2*hadamardCost)

	// thetaEvalCost is the cost of evaluating a 2-isogeny at both points.
	thetaEvalCost = 2 * (thetaSquareCost + thetaMulCost + 2*hadamardCost)

	// thetaStructureCost is the cost of the values for doubling on a new
	// codomain: three projective inversions of ten coordinates, with 27
	// multiplications each.
	thetaStructureCost = 3 * 27 * 10
)

// FourIsogenySplits returns the entries of fourIsogenySplits, as the lines
// of a Go composite literal.
func (set *paramSet) FourIsogenySplits() string {
	splits, _ := fourIsogenyStrategy(set.E / fourIsogenyDegreeLog)

	return formatSplits(splits)
}

// ThetaSplits returns the entries of thetaSplits, as the lines of a Go
// composite literal.
func (set *paramSet) ThetaSplits() string {
	splits, _ := thetaStrategy(set.E - thetaChainOffset)

	return formatSplits(splits)
}

// ThetaStackDepth returns the number of stack entries that the strategy of
// thetaSplits needs at most for an entry at any level.
func (set *paramSet) ThetaStackDepth() int {
	_, depth := thetaStrategy(set.E - thetaChainOffset)

	return depth
}

// formatSplits returns splits as the lines of a Go composite literal.
func formatSplits(splits []int) string {
	var out strings.Builder

	for idx, split := range splits {
		if idx%splitsPerLine == 0 {
			out.WriteString("\n\t")
		} else {
			out.WriteString(" ")
		}

		fmt.Fprintf(&out, "%d,", split)
	}

	return out.String() + "\n"
}

// FourIsogenyStackSize returns the number of points that the chain with the
// strategy of fourIsogenySplits keeps at most.
func (set *paramSet) FourIsogenyStackSize() int {
	_, depth := fourIsogenyStrategy(set.E / fourIsogenyDegreeLog)

	return depth
}

// fourIsogenyStrategy returns, for each level l from 0 to top, the number of
// multiplications by 4 that an optimal strategy applies to a point at level
// l before saving it, and the largest number of points that the strategy
// keeps for a point at level top. A point at level l needs l multiplications
// by 4 to generate a 4-isogeny, so it generates l + 1 steps of the chain.
//
// With cost[l] the cost of those steps, cost[0] = 0 and cost[l] is the
// minimum over 1 ≤ i ≤ l of i multiplications by 4, cost[l − i] for the
// steps of the new point, l − i + 1 evaluations of the saved point, and
// cost[i − 1] for the rest of its steps. The stack holds depth[l] points for
// a point at level l: the saved point below those of the new one, or
// afterwards those of the saved point.
func fourIsogenyStrategy(top int) ([]int, int) {
	cost := make([]int, top+1)
	splits := make([]int, top+1)
	depth := make([]int, top+1)
	depth[0] = 1

	for level := 1; level <= top; level++ {
		cost[level] = -1

		for split := 1; split <= level; split++ {
			total := split*quadrupleCost + cost[level-split] +
				(level-split+1)*fourIsogenyEvalCost + cost[split-1]
			if cost[level] < 0 || total < cost[level] {
				cost[level], splits[level] = total, split
			}
		}

		split := splits[level]
		depth[level] = max(1+depth[level-split], depth[split-1])
	}

	return splits, depth[top]
}

// thetaChainOffset is e minus the highest level of a theta point on the stack:
// the gluing counts as one step for two more 2-isogenies, and lowers the
// levels of the curve points it maps by one.
const thetaChainOffset = 3

// thetaStrategy returns, for each level l from 0 to top, the number of
// doublings that an optimal strategy applies to an entry of the theta chain
// at level l ≥ 2 before saving it, and the largest number of entries that the
// strategy keeps for an entry at a level up to top. An entry at level l
// needs l − 1 doublings before it determines a step, so it determines l
// steps.
//
// With cost[l] the cost of those steps, cost[1] = 0 and cost[l] is the
// minimum over 1 ≤ i < l of i doublings, cost[l − i] for the steps of the
// new entry, l − i evaluations of the saved entry, and, if the saved entry
// then needs doubling, the values for doubling on the new codomain and
// cost[i].
func thetaStrategy(top int) ([]int, int) {
	cost := make([]int, top+1)
	splits := make([]int, top+1)
	depth := make([]int, top+1)
	maxDepth := 1

	depth[1] = 1

	for level := 2; level <= top; level++ {
		cost[level] = -1

		for split := 1; split < level; split++ {
			total := split*thetaDoubleCost + cost[level-split] + (level-split)*thetaEvalCost
			if split > 1 {
				total += thetaStructureCost + cost[split]
			}

			if cost[level] < 0 || total < cost[level] {
				cost[level], splits[level] = total, split
			}
		}

		split := splits[level]
		depth[level] = max(1+depth[level-split], depth[split])
		maxDepth = max(maxDepth, depth[level])
	}

	return splits, maxDepth
}
