// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

// Command gen generates the per-prime packages internal/p308, internal/p374,
// and so on. Run it with "go generate" in the module root.
//
// The MIKE computations are written once, in internal/p308. Every prime gets
// its own package so that the field arithmetic is called directly, which
// lets the compiler keep temporaries on the stack. For each parameter set in
// params.txt, gen writes:
//
//   - fp_arith.go, the field constants and the unrolled field arithmetic;
//   - fpvec_arith_amd64.go, the same for the AVX2 field elements, which
//     hold four elements each;
//   - params.go, the MIKE parameter set;
//   - for primes other than p308, a copy of every other file of
//     internal/p308, tests included, with the package name changed.
package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"go/format"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"
)

const (
	// canonical is the package that the other per-prime packages are
	// copied from.
	canonical = "p308"

	dirPerm  = 0o750
	filePerm = 0o600
)

var (
	errParamSet      = errors.New("malformed parameter set")
	errPrimeSpecific = errors.New("prime-specific text in a copied file")
)

var (
	//go:embed params.txt
	paramSetsText string

	//go:embed params.go.tmpl
	paramsTemplate string
)

// paramSet is a MIKE parameter set, as described in params.txt.
type paramSet struct {
	Name     string // such as FastMIKE-I
	C, F, E  int
	A        string
	P, Q, PQ string
}

// Pkg returns the name of the package for the parameter set.
func (set *paramSet) Pkg() string { return fmt.Sprintf("p%d", set.F) }

// loadParamSets returns the parameter sets in params.txt.
func loadParamSets() ([]paramSet, error) {
	var sets []paramSet

	for line := range strings.Lines(paramSetsText) {
		if strings.HasPrefix(line, "#") {
			continue
		}

		var set paramSet

		_, err := fmt.Sscan(line, &set.Name, &set.C, &set.F, &set.E, &set.A, &set.P, &set.Q, &set.PQ)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", errParamSet, line, err)
		}

		sets = append(sets, set)
	}

	return sets, nil
}

func main() {
	err := update(".")
	if err != nil {
		log.Fatal(err)
	}
}

// update writes the generated files of the module rooted at dir and removes
// stale ones.
func update(dir string) error {
	fsys := os.DirFS(dir)

	files, err := generate(fsys)
	if err != nil {
		return err
	}

	stale, err := staleFiles(fsys, files)
	if err != nil {
		return err
	}

	for _, name := range stale {
		err := os.Remove(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return fmt.Errorf("removing a stale file: %w", err)
		}
	}

	for name, src := range files {
		name = filepath.Join(dir, filepath.FromSlash(name))

		err := os.MkdirAll(filepath.Dir(name), dirPerm)
		if err != nil {
			return fmt.Errorf("creating a package directory: %w", err)
		}

		err = os.WriteFile(name, src, filePerm)
		if err != nil {
			return fmt.Errorf("writing a generated file: %w", err)
		}
	}

	return nil
}

// staleFiles returns the Go files in the generated packages, other than the
// canonical one, that generate does not produce: leftovers of files removed
// from the canonical package.
func staleFiles(fsys fs.FS, files map[string][]byte) ([]string, error) {
	dirs := make(map[string]bool)
	for name := range files {
		dirs[path.Dir(name)] = true
	}

	delete(dirs, path.Join("internal", canonical))

	var stale []string

	for dir := range dirs {
		matches, err := fs.Glob(fsys, path.Join(dir, "*.go"))
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", dir, err)
		}

		for _, match := range matches {
			if _, ok := files[match]; !ok {
				stale = append(stale, match)
			}
		}
	}

	slices.Sort(stale)

	return stale, nil
}

// generate returns the contents of all generated files of the module in
// fsys, keyed by slash-separated paths relative to the module root.
func generate(fsys fs.FS) (map[string][]byte, error) {
	sets, err := loadParamSets()
	if err != nil {
		return nil, err
	}

	copied, err := canonicalFiles(fsys)
	if err != nil {
		return nil, err
	}

	files := make(map[string][]byte)

	for idx := range sets {
		set := &sets[idx]
		dir := path.Join("internal", set.Pkg())

		arith, err := genArith(set)
		if err != nil {
			return nil, err
		}

		params, err := execute("params.go", paramsTemplate, set)
		if err != nil {
			return nil, err
		}

		vecArith, err := genVecArith(set)
		if err != nil {
			return nil, err
		}

		files[path.Join(dir, "fp_arith.go")] = arith
		files[path.Join(dir, "fpvec_arith_amd64.go")] = vecArith
		files[path.Join(dir, "params.go")] = params

		if set.Pkg() == canonical {
			continue
		}

		for name, src := range copied {
			files[path.Join(dir, name)] = copyFile(src, set.Pkg())
		}
	}

	return files, nil
}

// isGenerated reports whether a file of a per-prime package is generated for
// every prime, rather than copied from the canonical package.
func isGenerated(name string) bool {
	return name == "fp_arith.go" || name == "fpvec_arith_amd64.go" || name == "params.go"
}

// canonicalFiles returns the files of the canonical package that are copied
// to the other packages.
func canonicalFiles(fsys fs.FS) (map[string][]byte, error) {
	dir := path.Join("internal", canonical)

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("reading the canonical package: %w", err)
	}

	files := make(map[string][]byte)
	mention := regexp.MustCompile(`(?i)p308|633`)

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || isGenerated(name) {
			continue
		}

		src, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("reading the canonical package: %w", err)
		}
		// Prime-specific values belong in the generated files. Anything
		// else would be copied verbatim into the wrong package.
		body := renamePackage(src, "")
		if loc := mention.FindIndex(body); loc != nil {
			return nil, fmt.Errorf("%s: %w: %q", name, errPrimeSpecific, body[loc[0]:loc[1]])
		}

		files[name] = src
	}

	return files, nil
}

// renamePackage returns src, a canonical file, with the package clause and
// the package comment, if any, naming package pkg.
func renamePackage(src []byte, pkg string) []byte {
	out := bytes.Replace(src, []byte("package "+canonical+"\n"), []byte("package "+pkg+"\n"), 1)

	return bytes.Replace(out, []byte("// Package "+canonical+" "), []byte("// Package "+pkg+" "), 1)
}

// copyFile returns src, a canonical file, adapted to package pkg.
func copyFile(src []byte, pkg string) []byte {
	header := fmt.Sprintf("// Code generated by internal/gen from internal/%s. DO NOT EDIT.\n\n", canonical)

	return append([]byte(header), renamePackage(src, pkg)...)
}

// execute runs the template text on data and returns the result, formatted
// as Go source. The name identifies the generated file in errors.
func execute(name, text string, data any) ([]byte, error) {
	tmpl, err := template.New(name).Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	out, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%s: %w\n%s", name, err, buf.Bytes())
	}

	return out, nil
}
