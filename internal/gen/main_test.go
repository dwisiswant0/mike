// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestGeneratedFilesUpToDate fails if running "go generate" in the module
// root would change any file.
func TestGeneratedFilesUpToDate(t *testing.T) {
	t.Parallel()

	fsys := os.DirFS(filepath.Join("..", ".."))

	files, err := generate(fsys)
	if err != nil {
		t.Fatal(err)
	}

	for name, want := range files {
		got, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Errorf("%s: %v; run go generate", name, err)

			continue
		}

		if !bytes.Equal(got, want) {
			t.Errorf("%s is out of date; run go generate", name)
		}
	}

	stale, err := staleFiles(fsys, files)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range stale {
		t.Errorf("%s is not generated anymore; run go generate", name)
	}
}
