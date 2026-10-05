package bench

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtractSkipsPaxGlobalHeader: every tarball git produces opens with a
// pax_global_header carrying the commit SHA, and GitHub's codeload archives
// all have one. Refusing it rejected real corpus snapshots outright, which is
// how the first Tier R entry failed to load. It is metadata, not a file, so
// it extracts to nothing and the scan proceeds.
func TestExtractSkipsPaxGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// Exactly what git writes: the entry carries the commit SHA as a PAX
	// comment record, and Go's writer requires PAXRecords for this type.
	if err := tw.WriteHeader(&tar.Header{
		Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader,
		PAXRecords: map[string]string{"comment": "d318b683471101618febed18996405ad26462110"},
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte("openai==1.0.0\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "repo-abc123/requirements.txt", Typeflag: tar.TypeReg,
		Size: int64(len(body)), Mode: 0o644,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	for _, c := range []io.Closer{tw, gz} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	arc := filepath.Join(dir, "snapshot.tar.gz")
	if err := os.WriteFile(arc, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := extractTarGz(arc, out); err != nil {
		t.Fatalf("extract rejected a normal git tarball: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(out, "repo-abc123", "requirements.txt"))
	if err != nil {
		t.Fatalf("the real file did not extract: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content = %q, want %q", got, body)
	}
	if _, err := os.Stat(filepath.Join(out, "pax_global_header")); err == nil {
		t.Error("pax_global_header was written as a file; it is metadata")
	}
}

// TestExtractRefusesEscapingEntries: the guard's contract is that no entry
// resolves outside the extraction root. It used to test for a ".." followed by
// a separator, which let an entry named exactly ".." through — filepath.Join
// then resolved it to the PARENT of dst. Nothing was written there (as a dir
// the MkdirAll is a no-op, as a file the Create hits EISDIR), so it failed safe
// by accident rather than by design. These are the shapes that must be refused
// outright, with "." kept alongside because it names the root itself.
func TestExtractRefusesEscapingEntries(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag byte
	}{
		{"..", tar.TypeDir},
		{"..", tar.TypeReg},
		{"../", tar.TypeDir},
		{"../escape", tar.TypeReg},
		{"../../escape", tar.TypeReg},
		{"a/../../escape", tar.TypeReg},
		{"/abs", tar.TypeReg},
		{".", tar.TypeDir},
	} {
		t.Run(tc.name+"-"+kindName(tc.flag), func(t *testing.T) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(&tar.Header{Name: tc.name, Typeflag: tc.flag, Size: 0, Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			src := filepath.Join(dir, "corpus.tar.gz")
			if err := os.WriteFile(src, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "out")
			if err := os.MkdirAll(dst, 0o750); err != nil {
				t.Fatal(err)
			}

			err := extractTarGz(src, dst)
			if err == nil {
				t.Fatalf("entry %q (type %c) was accepted; it must be refused", tc.name, tc.flag)
			}
			if !strings.Contains(err.Error(), "escapes the extraction root") {
				t.Fatalf("entry %q refused for the wrong reason: %v", tc.name, err)
			}
		})
	}
}

// TestExtractAcceptsOrdinaryEntries: the guard must not be so strict that it
// refuses the archives it exists to read.
func TestExtractAcceptsOrdinaryEntries(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("langchain==0.2.16\n")
	for _, h := range []*tar.Header{
		{Name: "repo/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "repo/requirements.txt", Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644},
		{Name: "repo/./nested/../app.py", Typeflag: tar.TypeReg, Size: 0, Mode: 0o644},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "corpus.tar.gz")
	if err := os.WriteFile(src, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out")
	if err := extractTarGz(src, dst); err != nil {
		t.Fatalf("ordinary archive refused: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "repo", "requirements.txt")); err != nil || string(got) != string(body) {
		t.Fatalf("requirements.txt = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "repo", "app.py")); err != nil {
		t.Fatalf("interior .. was not normalized to repo/app.py: %v", err)
	}
}

func kindName(flag byte) string {
	if flag == tar.TypeDir {
		return "dir"
	}
	return "file"
}
