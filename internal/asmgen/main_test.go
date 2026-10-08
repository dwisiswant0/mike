// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"testing"
)

// TestGeneratedFilesUpToDate fails if running "go generate" in the module
// root would change any assembly file.
func TestGeneratedFilesUpToDate(t *testing.T) {
	t.Parallel()

	fields, err := loadFields()
	if err != nil {
		t.Fatal(err)
	}

	for _, fld := range fields {
		want, err := generate(fld)
		if err != nil {
			t.Fatal(err)
		}

		got, err := os.ReadFile(fld.asmPath())
		if err != nil {
			t.Errorf("%v; run go generate", err)

			continue
		}

		if !bytes.Equal(got, want) {
			t.Errorf("%s is out of date; run go generate", fld.asmPath())
		}
	}
}
