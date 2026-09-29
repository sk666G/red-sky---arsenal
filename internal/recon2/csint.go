package recon2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Content-source intelligence. Reads a directory of text files (notes,
// scrapes, docs, logs) and builds a searchable index keyed by token.
//
// Two operations:
//   BuildIndex   walk a directory, tokenize each file, store a postings
//                list per token
//   Search       given a query, return ranked hits
//
// The tokenizer is ASCII word-splitting with lowercasing and a stop-word
// filter. The ranker is TF-IDF-lite: term frequency in the file times
// inverse document frequency across the corpus. No stemming, no
// phrase queries — those are follow-ups.

// Document is one indexed file.
type Document struct {
	Path    string         `json:"path"`
	Size    int64          `json:"size"`
	ModTime int64          `json:"mod_time"`
	Tokens  map[string]int `json:"tokens"` // token → count
	Hash    string         `json:"hash"`   // sha256 of contents
}

// Index is the searchable corpus.
type Index struct {
	Root     string               `json:"root"`
	BuiltAt  int64                `json:"built_at"`
	Docs     map[string]*Document `json:"docs"`     // path → doc
	Postings map[string][]string  `json:"postings"` // token → list of doc paths
}

// BuildIndexOptions controls index construction.
type BuildIndexOptions struct {
	MaxFileSize int64    // skip files larger than this; default 8MB
	Extensions  []string // if non-empty, only these extensions
	SkipDirs    []string // extra dir names to skip
}

// stopWords is a small English stop list.
var stopWords = map[string]struct{}{
	"the": {}, "and": {}, "for": {}, "are": {}, "but": {}, "not": {}, "you": {},
	"all": {}, "any": {}, "can": {}, "had": {}, "has": {}, "her": {}, "his": {},
	"how": {}, "its": {}, "may": {}, "new": {}, "now": {}, "old": {}, "our": {},
	"out": {}, "see": {}, "she": {}, "was": {}, "who": {}, "why": {}, "with": {},
	"this": {}, "that": {}, "from": {}, "they": {}, "been": {}, "have": {},
	"were": {}, "what": {}, "when": {}, "where": {}, "will": {}, "into": {},
	"than": {}, "then": {}, "them": {}, "some": {}, "such": {}, "only": {},
	"just": {}, "also": {}, "more": {}, "most": {}, "over": {}, "here": {},
}

// tokenRe matches word characters (letters + digits).
var tokenRe = regexp.MustCompile(`[A-Za-z0-9_]+`)

// Tokenize splits text into lowercase tokens, dropping stop words and
// tokens shorter than 2 characters.
func Tokenize(text string) []string {
	raw := tokenRe.FindAllString(text, -1)
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		t = strings.ToLower(t)
		if len(t) < 2 {
			continue
		}
		if _, skip := stopWords[t]; skip {
			continue
		}
		out = append(out, t)
	}
	return out
}

// BuildIndex walks root and builds an in-memory index.
func BuildIndex(root string, opts BuildIndexOptions) (*Index, error) {
	if root == "" {
		return nil, errors.New("recon2: root required")
	}
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = 8 * 1024 * 1024
	}
	extAllowed := map[string]bool{}
	for _, e := range opts.Extensions {
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		extAllowed[strings.ToLower(e)] = true
	}
	extraSkip := map[string]bool{}
	for _, d := range opts.SkipDirs {
		extraSkip[strings.ToLower(d)] = true
	}

	idx := &Index{
		Root:     root,
		BuiltAt:  time.Now().Unix(),
		Docs:     map[string]*Document{},
		Postings: map[string][]string{},
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if extraSkip[low] || low == ".git" || low == "node_modules" || low == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > opts.MaxFileSize || info.Size() == 0 {
			return nil
		}
		if len(extAllowed) > 0 {
			if !extAllowed[strings.ToLower(filepath.Ext(path))] {
				return nil
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// heuristic: skip binary files (any NUL in first 4KB)
		if hasNul(b[:min(len(b), 4096)]) {
			return nil
		}
		tokens := Tokenize(string(b))
		if len(tokens) == 0 {
			return nil
		}
		counts := map[string]int{}
		for _, t := range tokens {
			counts[t]++
		}
		sum := sha256.Sum256(b)
		doc := &Document{
			Path:    path,
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
			Tokens:  counts,
			Hash:    hex.EncodeToString(sum[:]),
		}
		idx.Docs[path] = doc
		for t := range counts {
			idx.Postings[t] = append(idx.Postings[t], path)
		}
		return nil
	})
	return idx, err
}

// SearchHit is one result.
type SearchHit struct {
	Path  string   `json:"path"`
	Score float64  `json:"score"`
	Terms []string `json:"terms"` // matched terms
}

// Search runs a query against the index. Terms are split the same way the
// index was built. Score = sum over terms of (tf * idf).
func (idx *Index) Search(query string) []SearchHit {
	terms := Tokenize(query)
	if len(terms) == 0 {
		return nil
	}
	scores := map[string]float64{}
	matched := map[string]map[string]struct{}{}
	nDocs := float64(len(idx.Docs))
	for _, t := range terms {
		posts := idx.Postings[t]
		if len(posts) == 0 {
			continue
		}
		idf := 1.0 + log2(nDocs/float64(len(posts)+1))
		for _, p := range posts {
			d := idx.Docs[p]
			if d == nil {
				continue
			}
			tf := float64(d.Tokens[t])
			scores[p] += tf * idf
			if matched[p] == nil {
				matched[p] = map[string]struct{}{}
			}
			matched[p][t] = struct{}{}
		}
	}
	var hits []SearchHit
	for p, s := range scores {
		var terms []string
		for t := range matched[p] {
			terms = append(terms, t)
		}
		sort.Strings(terms)
		hits = append(hits, SearchHit{Path: p, Score: s, Terms: terms})
	}
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].Score > hits[j].Score
	})
	return hits
}

// Save writes the index to a JSON file.
func (idx *Index) Save(path string) error {
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Load reads an index back from a JSON file.
func Load(path string) (*Index, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("recon2: parse index: %w", err)
	}
	return &idx, nil
}

// hasNul reports whether any byte in b is NUL — a quick binary-file sniff.
func hasNul(b []byte) bool {
	for _, x := range b {
		if x == 0 {
			return true
		}
	}
	return false
}

// min returns the smaller of a,b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// log2 wraps math.Log2 so callers in this file have a single name to
// change if the ranking formula ever moves.
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Log2(x)
}
