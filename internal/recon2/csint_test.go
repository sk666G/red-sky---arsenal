package recon2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTokenizeBasic checks lowercasing, stop-word filtering, and short
// token removal.
func TestTokenizeBasic(t *testing.T) {
	got := Tokenize("The quick brown fox jumps over the lazy dog")
	// stop words: the, over, the
	wantContains := []string{"quick", "brown", "fox", "jumps", "lazy", "dog"}
	for _, w := range wantContains {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Tokenize missing %q in %v", w, got)
		}
	}
	for _, g := range got {
		if g == "the" || g == "over" {
			t.Fatalf("stop word %q not filtered", g)
		}
	}
}

func TestTokenizeLowercases(t *testing.T) {
	got := Tokenize("HELLO World")
	// both should be lowercase
	for _, g := range got {
		if strings.ToLower(g) != g {
			t.Fatalf("token not lowercased: %q", g)
		}
	}
}

func TestTokenizeDigits(t *testing.T) {
	got := Tokenize("version 2 api_v3")
	want := []string{"version", "api_v3"}
	// "2" should be filtered (length < 2)
	for _, g := range got {
		if g == "2" {
			t.Fatalf("single-char digit not filtered")
		}
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q in %v", w, got)
		}
	}
}

// TestBuildIndexOnTempDir writes a couple of files and indexes them.
func TestBuildIndexOnTempDir(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "one.txt"),
		[]byte("the quick brown fox jumps over the lazy dog"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "two.txt"),
		[]byte("hello world this is a test of the tokenizer"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "three.txt"),
		[]byte("another quick test"), 0o644)

	idx, err := BuildIndex(tmp, BuildIndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Docs) != 3 {
		t.Fatalf("indexed %d docs, want 3", len(idx.Docs))
	}
	// "quick" should appear in docs one.txt and three.txt
	posts := idx.Postings["quick"]
	if len(posts) != 2 {
		t.Fatalf("'quick' postings = %d, want 2", len(posts))
	}
}

// TestBuildIndexSkipsGit checks that .git is skipped.
func TestBuildIndexSkipsGit(t *testing.T) {
	tmp := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tmp, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(tmp, ".git", "config"),
		[]byte("this should be skipped content here"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "kept.txt"),
		[]byte("this file will be indexed by the build"), 0o644)

	idx, err := BuildIndex(tmp, BuildIndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Docs) != 1 {
		t.Fatalf("indexed %d docs, want 1 (git dir should be skipped)", len(idx.Docs))
	}
}

// TestBuildIndexSkipsBinary confirms the NUL sniff.
func TestBuildIndexSkipsBinary(t *testing.T) {
	tmp := t.TempDir()
	// binary file with NUL in the first bytes
	bin := []byte{0x7F, 0x45, 0x4C, 0x46, 0x00, 0x00, 0x01, 0x02}
	_ = os.WriteFile(filepath.Join(tmp, "bin.elf"), bin, 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "text.txt"),
		[]byte("this is a text file with real tokens here"), 0o644)

	idx, err := BuildIndex(tmp, BuildIndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Docs) != 1 {
		t.Fatalf("indexed %d docs, want 1 (binary should be skipped)", len(idx.Docs))
	}
	for _, d := range idx.Docs {
		if strings.HasSuffix(d.Path, ".elf") {
			t.Fatalf("binary file was indexed: %s", d.Path)
		}
	}
}

// TestSearchFindsRelevantDoc writes two docs, checks that a query for the
// distinctive term ranks the right one.
func TestSearchFindsRelevantDoc(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "alpha.txt"),
		[]byte("alpha alpha alpha bravo charlie"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "bravo.txt"),
		[]byte("bravo bravo bravo charlie delta"), 0o644)

	idx, err := BuildIndex(tmp, BuildIndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hits := idx.Search("alpha")
	if len(hits) == 0 {
		t.Fatalf("search for 'alpha' returned nothing")
	}
	if !strings.HasSuffix(hits[0].Path, "alpha.txt") {
		t.Fatalf("top hit wrong: %s", hits[0].Path)
	}
}

// TestSearchTFIDFScoring confirms that a term more frequent in one doc
// scores higher for that doc.
func TestSearchTFIDFScoring(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "rare.txt"),
		[]byte("one token here"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "common.txt"),
		[]byte("token token token token token"), 0o644)

	idx, _ := BuildIndex(tmp, BuildIndexOptions{})
	hits := idx.Search("token")
	if len(hits) != 2 {
		t.Fatalf("want 2 hits, got %d", len(hits))
	}
	if !strings.HasSuffix(hits[0].Path, "common.txt") {
		t.Fatalf("higher-freq doc did not rank first: %v", hits[0])
	}
}

// TestSearchEmptyQuery returns nothing for empty input.
func TestSearchEmptyQuery(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "x.txt"), []byte("hello world"), 0o644)
	idx, _ := BuildIndex(tmp, BuildIndexOptions{})
	hits := idx.Search("")
	if len(hits) != 0 {
		t.Fatalf("empty query returned %d hits", len(hits))
	}
	// stop-words only query should also return nothing
	hits = idx.Search("the and of")
	if len(hits) != 0 {
		t.Fatalf("stopword-only query returned %d hits", len(hits))
	}
}

// TestIndexSaveLoad round-trips the index through JSON.
func TestIndexSaveLoad(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "doc.txt"),
		[]byte("unique content unique unique token"), 0o644)
	idx, _ := BuildIndex(tmp, BuildIndexOptions{})

	idxPath := filepath.Join(tmp, ".rs_csint.json")
	if err := idx.Save(idxPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Docs) != len(idx.Docs) {
		t.Fatalf("loaded %d docs, orig %d", len(loaded.Docs), len(idx.Docs))
	}
	// search should still work
	hits := loaded.Search("unique")
	if len(hits) == 0 {
		t.Fatalf("loaded index search returned nothing")
	}
}

// TestExtensionFilter confirms the extension allow-list works.
func TestExtensionFilter(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("txt content"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "b.md"), []byte("md content"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "c.bin"), []byte("bin content"), 0o644)

	idx, _ := BuildIndex(tmp, BuildIndexOptions{Extensions: []string{".txt", ".md"}})
	if len(idx.Docs) != 2 {
		t.Fatalf("extension filter: indexed %d docs, want 2", len(idx.Docs))
	}
}

// TestSkipDirOption confirms the extra SkipDirs are honored.
func TestSkipDirOption(t *testing.T) {
	tmp := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tmp, "node_modules"), 0o755)
	_ = os.WriteFile(filepath.Join(tmp, "node_modules", "x.txt"), []byte("skip me"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "keep.txt"), []byte("keep me"), 0o644)

	idx, _ := BuildIndex(tmp, BuildIndexOptions{SkipDirs: []string{"node_modules"}})
	if len(idx.Docs) != 1 {
		t.Fatalf("skip dir: indexed %d docs, want 1", len(idx.Docs))
	}
}
