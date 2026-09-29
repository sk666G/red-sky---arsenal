package cryptogo

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

// HashCrackResult is the outcome of a wordlist crack.
type HashCrackResult struct {
	Found    bool
	Word     string
	Tried    int64
	Elapsed  time.Duration
}

// HashAlgorithm identifies which hash to compute per word.
const (
	AlgoMD5    = "md5"
	AlgoSHA1   = "sha1"
	AlgoSHA224 = "sha224"
	AlgoSHA256 = "sha256"
	AlgoSHA384 = "sha384"
	AlgoSHA512 = "sha512"
	AlgoNTLM   = "ntlm"
)

// HashOne returns the hex digest of one word under the given algorithm.
func HashOne(algo string, word []byte) (string, error) {
	switch algo {
	case AlgoMD5:
		h := md5.Sum(word)
		return hex.EncodeToString(h[:]), nil
	case AlgoSHA1:
		h := sha1.Sum(word)
		return hex.EncodeToString(h[:]), nil
	case AlgoSHA224:
		h := sha256.Sum224(word)
		return hex.EncodeToString(h[:]), nil
	case AlgoSHA256:
		h := sha256.Sum256(word)
		return hex.EncodeToString(h[:]), nil
	case AlgoSHA384:
		h := sha512.Sum384(word)
		return hex.EncodeToString(h[:]), nil
	case AlgoSHA512:
		h := sha512.Sum512(word)
		return hex.EncodeToString(h[:]), nil
	case AlgoNTLM:
		return NTLMHex(word), nil
	default:
		return "", fmt.Errorf("cryptogo/hash_crack: unknown algo %q", algo)
	}
}

// NTLMHex computes the NTLM hash of a password: hex(MD4(UTF-16LE(pw))).
func NTLMHex(password []byte) string {
	runes := []rune(string(password))
	u16 := utf16.Encode(runes)
	buf := make([]byte, len(u16)*2)
	for i, w := range u16 {
		buf[i*2] = byte(w)
		buf[i*2+1] = byte(w >> 8)
	}
	h := MD4(buf)
	return hex.EncodeToString(h)
}

// CrackHash runs a wordlist against a target hex digest. Calls onProgress
// every `progressEvery` words (if non-nil). Returns when the target is
// matched or the wordlist is exhausted.
func CrackHash(algo, targetHex, wordlistPath string, onProgress func(int64)) (HashCrackResult, error) {
	var res HashCrackResult
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()

	target := strings.ToLower(strings.TrimSpace(targetHex))
	if target == "" {
		return res, errors.New("cryptogo/hash_crack: empty target")
	}

	f, err := os.Open(wordlistPath)
	if err != nil {
		return res, fmt.Errorf("cryptogo/hash_crack: open: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var n int64
	for sc.Scan() {
		word := sc.Bytes()
		got, err := HashOne(algo, word)
		if err != nil {
			return res, err
		}
		n++
		if got == target {
			res.Found = true
			res.Word = string(word)
			res.Tried = n
			return res, nil
		}
		if onProgress != nil && n%100000 == 0 {
			onProgress(n)
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return res, fmt.Errorf("cryptogo/hash_crack: scan: %w", err)
	}
	res.Tried = n
	return res, nil
}

// IdentifyHash classifies a hash by shape. Returns every matching label.
// Ambiguous (md5 vs ntlm both 32 hex) returns both.
func IdentifyHash(h string) []string {
	h = strings.TrimSpace(h)
	var matches []string
	lower := strings.ToLower(h)
	isHex := true
	for _, c := range lower {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			isHex = false
			break
		}
	}
	if isHex {
		switch len(h) {
		case 16:
			matches = append(matches, "mysql4")
		case 32:
			matches = append(matches, "md5", "ntlm")
		case 40:
			matches = append(matches, "sha1")
		case 56:
			matches = append(matches, "sha224")
		case 64:
			matches = append(matches, "sha256")
		case 96:
			matches = append(matches, "sha384")
		case 128:
			matches = append(matches, "sha512")
		}
	}
	// bcrypt
	if strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$") {
		matches = append(matches, "bcrypt")
	}
	// md5crypt
	if strings.HasPrefix(h, "$1$") {
		matches = append(matches, "md5crypt")
	}
	// sha256crypt
	if strings.HasPrefix(h, "$5$") {
		matches = append(matches, "sha256crypt")
	}
	// sha512crypt
	if strings.HasPrefix(h, "$6$") {
		matches = append(matches, "sha512crypt")
	}
	// argon2
	if strings.HasPrefix(h, "$argon2") {
		matches = append(matches, "argon2")
	}
	// phpass
	if strings.HasPrefix(h, "$P$") {
		matches = append(matches, "phpass")
	}
	// jwt
	if strings.Count(h, ".") == 2 && strings.HasPrefix(h, "eyJ") {
		matches = append(matches, "jwt_hs256")
	}
	return matches
}
