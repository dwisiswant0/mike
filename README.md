# mike

[![Go Reference](https://pkg.go.dev/badge/go.dw1.io/mike.svg)](https://pkg.go.dev/go.dw1.io/mike)

Package mike implements MIKE (Module Isogeny Key Exchange) in Go. MIKE is a
post-quantum *non-interactive key exchange* (*NIKE*): two parties who know
each other's public keys compute the same shared secret, like Diffie-Hellman,
with no further messages[^1].

> [!WARNING]
> MIKE was published in 2026, and its cryptanalysis has only begun. Its
> parameters might change. This package hasn't been audited. Do NOT rely on it
> alone to protect data.

## Install

The package requires Go 1.27 or later.

```sh
go get go.dw1.io/mike
```

Then import it:

```go
import "go.dw1.io/mike"
```

## Compute a shared secret

Each party generates a key pair and publishes the encoded public key. Then each
side computes the shared secret from its private key and the peer's public key.
The following excerpt shows Alice's side, in a function that returns an error:

```go
alice, err := mike.Fast1().GenerateKey()
if err != nil {
	return err
}

// Send alice.PublicKey().Bytes() to Bob, and receive bobBytes.
bobPub, err := mike.Fast1().NewPublicKey(bobBytes)
if err != nil {
	return err
}
secret, err := alice.SharedSecret(bobPub)
if err != nil {
	return err // bobPub is not a valid MIKE public key.
}
```

`SharedSecret` returns 32 bytes. As with Diffie-Hellman, don't use them as a
key directly. Derive keys with a *key derivation function* (*KDF*), such as
HKDF, that also binds both public keys and, where they exist, the identities
of the two parties. This is the construction that the paper proves secure.

To restore a private key, pass the bytes from `PrivateKey.Bytes` to
`ParameterSet.NewPrivateKey`. This recomputes the public key, which takes as
long as generating a key.

## Parameter sets

The package provides the six parameter sets from the paper. Each uses a prime
$`p = c \cdot 2^f - 1`$ and a secret isogeny of degree $`2^e`$.

| Function    | Variant      | NIST level | $`p`$                     | $`e`$ | Public key | Private key |
| ----------- | ------------ | ---------- | ------------------------- | ----- | ---------- | ----------- |
| `Fast1`     | FastMIKE     | I          | $`633 \cdot 2^{308} - 1`$ | 228   | 80 bytes   | 29 bytes    |
| `Fast3`     | FastMIKE     | III        | $`593 \cdot 2^{474} - 1`$ | 340   | 122 bytes  | 43 bytes    |
| `Fast5`     | FastMIKE     | V          | $`317 \cdot 2^{628} - 1`$ | 452   | 160 bytes  | 57 bytes    |
| `Rigorous1` | RigorousMIKE | I          | $`117 \cdot 2^{374} - 1`$ | 372   | 96 bytes   | 47 bytes    |
| `Rigorous3` | RigorousMIKE | III        | $`77 \cdot 2^{566} - 1`$  | 564   | 144 bytes  | 71 bytes    |
| `Rigorous5` | RigorousMIKE | V          | $`41 \cdot 2^{758} - 1`$  | 756   | 192 bytes  | 95 bytes    |

FastMIKE uses more aggressive, though still conservative, parameters. Its
security proof also assumes that its public keys are indistinguishable from
random supersingular curves. RigorousMIKE does not need that assumption.

## Performance

The following times are for one operation on one core of an AMD EPYC 7763, with
Go 1.27.1 on linux/amd64. Each time is the median of 8 runs, with the runs of
the builds interleaved.

On amd64, two optional speedups are available: the
[BMI2 and ADX instructions](#bmi2-and-adx-instructions) for the arithmetic, and
[AVX2 vector code](#avx2-vector-code) for `SharedSecret`. The columns show each
combination:

- **Go**: neither, as in a build with the `purego` tag and on other
  architectures.
- **BMI2 + ADX**: the BMI2 and ADX instructions, as in the default build.
- **AVX2**: the vector code, in a build with `GOEXPERIMENT=simd` and the
  `purego` tag.
- **BMI2 + ADX and AVX2**: both, in a build with `GOEXPERIMENT=simd`.

`GenerateKey` doesn't use the vector code:

| Parameter set | Go      | BMI2 + ADX |
| ------------- | ------- | ---------- |
| `Fast1`       | 0.93 ms | 0.62 ms    |
| `Fast3`       | 3.0 ms  | 2.0 ms     |
| `Fast5`       | 10.8 ms | 4.1 ms     |
| `Rigorous1`   | 2.0 ms  | 1.4 ms     |
| `Rigorous3`   | 10.9 ms | 4.2 ms     |
| `Rigorous5`   | 32 ms   | 10.7 ms    |

`SharedSecret`:

| Parameter set | Go      | BMI2 + ADX | AVX2    | BMI2 + ADX and AVX2 |
| ------------- | ------- | ---------- | ------- | ------------------- |
| `Fast1`       | 6.7 ms  | 4.2 ms     | 4.1 ms  | 3.6 ms              |
| `Fast3`       | 21 ms   | 13.8 ms    | 14.5 ms | 12.4 ms             |
| `Fast5`       | 60 ms   | 27 ms      | 38 ms   | 26 ms               |
| `Rigorous1`   | 14.0 ms | 9.7 ms     | 9.2 ms  | 8.2 ms              |
| `Rigorous3`   | 60 ms   | 28 ms      | 38 ms   | 25 ms               |
| `Rigorous5`   | 179 ms  | 68 ms      | 98 ms   | 64 ms               |

Without the BMI2 and ADX instructions, the times of the larger parameter sets
depend on where the linker places the code. For example, `GenerateKey` runs the
same Go code in the build with the vector code, where it took 11.2 ms for
`Fast5` and 12.6 ms for `Rigorous3`.

`NewPrivateKey` takes about as long as `GenerateKey`; `NewPublicKey` runs only
the inexpensive checks, which take less than a microsecond for `Fast1`.

To run the benchmarks of the default build the same way, and summarize them
with [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat):

```sh
go test -run '^$' -bench . -benchmem -cpu 1 -count 10 > bench.txt
benchstat bench.txt
```

### BMI2 and ADX instructions

On amd64, multiplication and squaring in $`\mathrm{GF}(p)`$ and
$`\mathrm{GF}(p^2)`$, and the Hadamard transform of theta points, use the BMI2
and ADX instructions if the CPU supports them, as Intel CPUs do since Broadwell
and AMD CPUs since Zen. On other CPUs and architectures, and in builds with the
`purego` tag, they run the Go code instead. Both give the same results.

On the machine above, the BMI2 and ADX instructions cut the time of
`GenerateKey` by 33% to 67% and that of `SharedSecret` by 31% to 62%, compared
with the Go code. The parameter sets with the largest primes gain the most. To
compare the two:

```sh
go test -tags purego -run '^$' -bench . -benchmem -cpu 1 -count 10 > purego.txt
benchstat purego.txt bench.txt
```

### AVX2 vector code

On amd64, `SharedSecret` can use AVX2 vector code. It needs the experimental
`simd/archsimd` package of Go 1.27, so it's compiled only when you build with
`GOEXPERIMENT=simd`.

In such a build, the package uses the vector code if the CPU supports AVX2,
and the scalar code otherwise. Both give the same results. On the machine above,
the vector code cuts the time of `SharedSecret` by 31% to 45% with the Go field
arithmetic, and by 5% to 15% with the BMI2 and ADX instructions.

The vector code computes the dimension-4 isogeny chain, which takes most of
the time of `SharedSecret`, and allocates 40 KiB to 136 KiB more per call.
`GenerateKey` doesn't use it.

The `archsimd` API is experimental and might change in a later Go release. The
default build doesn't depend on it. To compare the two builds:

```sh
GOEXPERIMENT=simd go test -run '^$' -bench . -benchmem -cpu 1 -count 10 > simd.txt
benchstat bench.txt simd.txt
```

## Compatibility

Keys and shared secrets match the Rust reference implementation. The file
`testdata/vectors.txt` holds 108 keys and 96 shared secrets generated with it:

- The keys with indices 0 and 1 and their shared secret are the known-answer
  tests of the Rust reference, for all six parameter sets. For FastMIKE, the
  Python reference has the same tests.
- The other vectors cover both ways the torsion basis is sampled.

The tests check every vector, and that `GenerateKey` derives the reference's
private keys from the same random bytes.

Public keys must be in the normalized form that key generation produces, as
in the default configuration of the Rust reference.

## Security considerations

- Computations that involve the private key run in constant time: they don't
  branch on secret data or use it to index memory. This property comes from
  how the code is written and was checked by code review, not by measurement
  or formal verification. The field arithmetic uses `math/bits`, whose
  `Add64`, `Sub64`, and `Mul64` functions run in constant time. The AVX2
  vector code follows the same rules, and the assembly for the BMI2 and ADX
  instructions has no branches and selects results with masks or `CMOV`.
- `NewPublicKey` rejects non-canonical encodings and curves defined over
  $`\mathrm{GF}(p)`$. `SharedSecret` also checks that the peer's curve is
  supersingular and normalized, and returns an error otherwise. These checks
  reuse values that the computation needs anyway, so they cost little.
- `GenerateKey` uses `crypto/rand`. For deterministic tests, use
  [`testing/cryptotest.SetGlobalRandom`](https://pkg.go.dev/testing/cryptotest#SetGlobalRandom).

## Design

The root package `mike` holds the API. The math lives in one package per prime,
`internal/p308`, `internal/p374`, and so on:

- `internal/p308` is written by hand. It contains the field arithmetic helpers,
  $`\mathrm{GF}(p^2)`$, Montgomery curves, the dimension-1 isogeny chain of key
  generation, theta structures, the gluing isogenies, and the dimension-4
  isogeny chain of the shared secret.
- `internal/gen` reads the parameter sets from `internal/gen/params.txt`. It
  generates the unrolled field arithmetic (`fp_arith.go` and
  `fpvec_arith_amd64.go`) and the parameters (`params.go`) for each prime, and
  copies the other files of `internal/p308` into the other packages.
- For each prime, `internal/asmgen` uses
  [avo](https://github.com/mmcloughlin/avo) to generate `fp_amd64.s`, the
  assembly for the BMI2 and ADX instructions. It's a module of its own, so that
  the `mike` module doesn't depend on avo.

With one package per prime, each field operation is a direct call, and its
temporaries stay on the stack. Two generic designs were measured during
development and dropped:

- With type parameters for the field methods, temporaries escaped to the heap:
  about 90,000 allocations per shared secret.
- With a type switch per field operation, the dispatch took about a third of
  the run time.

The AVX2 vector code stores four elements of $`\mathrm{GF}(p)`$ in 256-bit
vectors, one element per 64-bit lane: vector $`i`$ holds limb $`i`$ of each
element, with limbs of 29 or 30 bits. At that size, `VPMULUDQ` can multiply two
limbs, and the columns of a product sum without carries. The 16 coordinates of
a theta point in the dimension-4 chain fit in four such groups of vectors. The
code uses `simd/archsimd` because the portable `simd` package of Go 1.27 has no
widening multiplication. Tests check that its results match the scalar code
exactly.

With the BMI2 and ADX instructions, the field multiplication works row by row.
Each row adds $`x \cdot y_i`$ to the accumulator with `MULX`, in two carry
chains, `ADCX` for the low halves of the products and `ADOX` for the high
halves, and then reduces the accumulator by one limb. Because $`p + 1`$ is a
multiple of $`2^{64(N-1)}`$, where $`N`$ is the number of limbs, that reduction
takes a single multiplication. Up to 9 limbs, the accumulator stays in
registers. For 10 and 12 limbs, $`x`$ is copied to the stack to free a register,
and for 12 limbs, two limbs of the accumulator live there too.

Squaring computes each cross product once, which takes about half the
multiplications. It works in three phases: it sums the cross products row by
row, doubles them and adds the squares of the limbs, and then reduces the
product. The quotient limbs of that reduction are limbs of the product, so its
multiplications don't depend on each other. As much of the product as fits
stays in registers: all limbs but one for 5 and 6 limbs. In
$`\mathrm{GF}(p^2)`$, a multiplication takes three multiplications in
$`\mathrm{GF}(p)`$ and a squaring two, on sums that aren't reduced. For 12
limbs, the code calls the $`\mathrm{GF}(p)`$ multiplication instead of
repeating it, which measured faster. The Hadamard transform keeps each sum and
difference in registers.

The Go compiler uses neither `MULX` nor `ADCX` and `ADOX`, and it spills much
of the unrolled Go code to the stack: for 12 limbs, 1,043 of the 1,717
instructions of the Go multiplication access the stack.

Both isogeny chains save intermediate multiples of the kernel points on a
stack. Rather than halving the remaining length at each split, they follow
optimal strategies for the costs of their steps, which `internal/gen` computes
by dynamic programming and stores in `params.go`. Before the gluing, the
dimension-4 chain halves the length on $`E`$, where doubling is cheaper, and
doubles only $`[n]P`$ and $`[n]Q`$: it gets the other generators by adding
multiples of $`P`$ and $`Q`$, which the kernel of the gluing needs anyway.

To change the code, see [CONTRIBUTING](/docs/CONTRIBUTING.md).

## License

Apache License, Version 2.0. See [LICENSE](/LICENSE) and [NOTICE](/NOTICE).

This package is a port of the [Rust reference implementation](https://github.com/tensor-mike/mike_rs)
by the MIKE team, which is also licensed under Apache 2.0.

[^1]: [MIKE: a fast and compact post-quantum NIKE](https://mike.isogeni.es).