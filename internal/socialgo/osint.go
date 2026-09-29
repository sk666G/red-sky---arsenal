// Package socialgo implements social-engineering recon primitives on the
// agent. It is the Go analogue of Program/social/ and shares the platform
// list and DNS brute wordlist with the Python side.
//
// The Go side focuses on the pieces that are pure network I/O — username
// enumeration, gravatar lookup, subdomain brute. Pretext rendering (the
// template library in Program/social/pretext.py) is a string operation
// and stays Python-side.
package socialgo

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Platform describes one site's username-lookup shape.
type Platform struct {
	Label       string
	URLTemplate string // {u} is replaced with the username
	Fingerprint string // positive string, or "" for status-code only
}

// Platforms is the same list Program/social/osint.py walks.
var Platforms = []Platform{
	{"github", "https://github.com/{u}", ""},
	{"twitter", "https://nitter.net/{u}", ""},
	{"reddit", "https://www.reddit.com/user/{u}", "u/{u}"},
	{"instagram", "https://www.instagram.com/{u}/", "\"username\":\"{u}\""},
	{"tiktok", "https://www.tiktok.com/@{u}", "\"uniqueId\":\"{u}\""},
	{"youtube", "https://www.youtube.com/@{u}", "\"channelId\""},
	{"twitch", "https://www.twitch.tv/{u}", ""},
	{"steam", "https://steamcommunity.com/id/{u}", "profile_header"},
	{"roblox", "https://www.roblox.com/user.aspx?username={u}", "profile-header"},
	{"telegram", "https://t.me/{u}", "tgme_page"},
	{"keybase", "https://keybase.io/{u}", "\"username\":\"{u}\""},
	{"medium", "https://medium.com/@{u}", ""},
	{"devto", "https://dev.to/{u}", "\"username\":\"{u}\""},
	{"hackernews", "https://news.ycombinator.com/user?id={u}", "karma"},
	{"pinterest", "https://www.pinterest.com/{u}/", ""},
	{"soundcloud", "https://soundcloud.com/{u}", ""},
	{"spotify", "https://open.spotify.com/user/{u}", ""},
	{"behance", "https://www.behance.net/{u}", ""},
	{"dribbble", "https://dribbble.com/{u}", ""},
	{"gitlab", "https://gitlab.com/{u}", ""},
	{"bitbucket", "https://bitbucket.org/{u}/", ""},
	{"npm", "https://www.npmjs.com/~{u}", ""},
	{"pypi", "https://pypi.org/user/{u}/", ""},
	{"crates", "https://crates.io/users/{u}", ""},
	{"docker", "https://hub.docker.com/u/{u}", ""},
	{"stackoverflow", "https://stackoverflow.com/users/filter?search={u}", "user-details"},
	{"mastodon_social", "https://mastodon.social/@{u}", ""},
	{"threads", "https://www.threads.net/@{u}", ""},
	{"bluesky", "https://bsky.app/profile/{u}", ""},
	{"patreon", "https://www.patreon.com/{u}", ""},
	{"onlyfans", "https://onlyfans.com/{u}", ""},
	{"flickr", "https://www.flickr.com/people/{u}/", ""},
	{"vimeo", "https://vimeo.com/{u}", ""},
	{"about.me", "https://about.me/{u}", ""},
	{"linktr", "https://linktr.ee/{u}", ""},
}

// PlatformHit is one positive match.
type PlatformHit struct {
	Label string `json:"platform"`
	URL   string `json:"url"`
}

// UsernameOptions controls a username enumeration.
type UsernameOptions struct {
	User      string
	Timeout   time.Duration // per request; default 8s
	Threads   int           // default 10
}

// checkPlatform hits one platform and reports whether it matched.
func checkPlatform(ctx context.Context, u string, p Platform, timeout time.Duration) (PlatformHit, bool) {
	url := strings.ReplaceAll(p.URLTemplate, "{u}", u)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PlatformHit{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return PlatformHit{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return PlatformHit{}, false
	}
	// fingerprint check
	if p.Fingerprint != "" {
		buf := make([]byte, 8192)
		n, _ := resp.Body.Read(buf)
		body := strings.ToLower(string(buf[:n]))
		fp := strings.ToLower(strings.ReplaceAll(p.Fingerprint, "{u}", u))
		if !strings.Contains(body, fp) {
			return PlatformHit{}, false
		}
	}
	// soft-404 detection — first few KB
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	low := strings.ToLower(string(buf[:n]))
	for _, marker := range []string{"not found", "doesn't exist", "user not exist"} {
		if strings.Contains(low, marker) {
			return PlatformHit{}, false
		}
	}
	return PlatformHit{Label: p.Label, URL: url}, true
}

// EnumerateUsername walks Platforms for the given handle and returns every
// hit. Concurrent across Threads goroutines. onHit is called per positive
// match, onMiss per negative — both optional.
func EnumerateUsername(ctx context.Context, opts UsernameOptions,
	onHit func(PlatformHit),
	onMiss func(label, reason string)) ([]PlatformHit, error) {
	if opts.User == "" {
		return nil, fmt.Errorf("socialgo: user required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.Threads <= 0 {
		opts.Threads = 10
	}

	type result struct {
		hit PlatformHit
		ok  bool
		p   Platform
	}
	jobs := make(chan Platform, len(Platforms))
	for _, p := range Platforms {
		jobs <- p
	}
	close(jobs)

	results := make(chan result, len(Platforms))
	var wg sync.WaitGroup
	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				hit, ok := checkPlatform(ctx, opts.User, p, opts.Timeout)
				results <- result{hit: hit, ok: ok, p: p}
			}
		}()
	}
	wg.Wait()
	close(results)

	var hits []PlatformHit
	for r := range results {
		if r.ok {
			hits = append(hits, r.hit)
			if onHit != nil {
				onHit(r.hit)
			}
		} else if onMiss != nil {
			onMiss(r.p.Label, "")
		}
	}
	return hits, nil
}

// GravatarResult is the outcome of a gravatar lookup.
type GravatarResult struct {
	Hash    string
	URL     string
	Found   bool
	Body    string
}

// Gravatar looks up a profile by email. If the email has a gravatar, the
// profile JSON is returned in Body.
func Gravatar(ctx context.Context, email string, timeout time.Duration) (GravatarResult, error) {
	if email == "" {
		return GravatarResult{}, fmt.Errorf("socialgo: email required")
	}
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	md5sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	hash := hex.EncodeToString(md5sum[:])
	profileURL := "https://www.gravatar.com/" + hash + ".json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return GravatarResult{Hash: hash}, err
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return GravatarResult{Hash: hash}, err
	}
	defer resp.Body.Close()
	out := GravatarResult{Hash: hash, URL: "https://www.gravatar.com/" + hash}
	if resp.StatusCode != 200 {
		return out, nil
	}
	buf := make([]byte, 32*1024)
	n, _ := resp.Body.Read(buf)
	out.Found = true
	out.Body = string(buf[:n])
	return out, nil
}

// SubdomainWordlist is the same candidate list Program/social/osint.py uses.
var SubdomainWordlist = []string{
	"www", "mail", "smtp", "imap", "pop", "webmail", "mx", "autodiscover",
	"vpn", "remote", "rdp", "ssh", "ftp", "sftp", "dev", "staging", "stage",
	"test", "qa", "prod", "api", "app", "apps", "dashboard", "admin",
	"portal", "internal", "intranet", "cloud", "storage", "media", "static",
	"cdn", "assets", "img", "images", "docs", "wiki", "confluence", "jira",
	"git", "gitlab", "github", "jenkins", "ci", "cd", "build", "monitor",
	"grafana", "prometheus", "kibana", "elastic", "db", "database", "sql",
	"mysql", "postgres", "redis", "cache", "auth", "sso", "login", "id",
	"oauth", "ns1", "ns2", "dns", "backup", "old", "legacy",
}

// SubdomainHit is one positive subdomain resolution.
type SubdomainHit struct {
	Sub  string
	Host string
	IP   string
}

// EnumerateSubdomains brutes SubdomainWordlist against domain, returning
// every subdomain that resolves.
func EnumerateSubdomains(ctx context.Context, domain string, words []string, threads int, onHit func(SubdomainHit)) ([]SubdomainHit, error) {
	if domain == "" {
		return nil, fmt.Errorf("socialgo: domain required")
	}
	if len(words) == 0 {
		words = SubdomainWordlist
	}
	if threads <= 0 {
		threads = 30
	}

	jobs := make(chan string, len(words))
	for _, w := range words {
		jobs <- w
	}
	close(jobs)

	results := make(chan SubdomainHit, len(words))
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver := &net.Resolver{}
			for w := range jobs {
				host := w + "." + domain
				ips, err := resolver.LookupHost(ctx, host)
				if err != nil || len(ips) == 0 {
					continue
				}
				h := SubdomainHit{Sub: w, Host: host, IP: ips[0]}
				results <- h
				if onHit != nil {
					onHit(h)
				}
			}
		}()
	}
	wg.Wait()
	close(results)

	var hits []SubdomainHit
	for h := range results {
		hits = append(hits, h)
	}
	return hits, nil
}
