package sandbox

import (
	"path/filepath"
	"regexp"
	"strings"

	"scbox/internal/third_party/esbuild/pkg/api"

	"scbox/internal/trace"
)

// Static ESM import forms, rewritten to require() so a top-level-await module can
// be wrapped in an async IIFE (esbuild won't lower import+TLA to CommonJS itself).
var (
	reImpDefaultNamed = regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"];?`)
	reImpNamespace    = regexp.MustCompile(`(?m)^\s*import\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*['"]([^'"]+)['"];?`)
	reImpNamed        = regexp.MustCompile(`(?m)^\s*import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"];?`)
	reImpDefault      = regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z_$][\w$]*)\s*from\s*['"]([^'"]+)['"];?`)
	reImpBare         = regexp.MustCompile(`(?m)^\s*import\s*['"]([^'"]+)['"];?`)
	reExpDefault      = regexp.MustCompile(`(?m)^\s*export\s+default\s+`)
	reExpDecl         = regexp.MustCompile(`(?m)^\s*export\s+(const|let|var|function|class|async|function\*)\b`)
	reExpList         = regexp.MustCompile(`(?m)^\s*export\s*\{[^}]*\}\s*;?`)
)

// esmImportsToRequire rewrites static ESM import/export statements to CommonJS so
// the source can run inside an async IIFE under goja (used only for top-level-await
// modules). Named bindings keep their `x as y` aliases as `x: y` destructuring.
// Dynamic `import()` calls are left for esbuild to lower.
func esmImportsToRequire(s string) string {
	fixAs := func(names string) string { return strings.ReplaceAll(names, " as ", ": ") }
	s = reImpDefaultNamed.ReplaceAllStringFunc(s, func(m string) string {
		g := reImpDefaultNamed.FindStringSubmatch(m)
		return "const " + g[1] + " = require('" + g[3] + "'); const {" + fixAs(g[2]) + "} = require('" + g[3] + "');"
	})
	s = reImpNamespace.ReplaceAllString(s, "const $1 = require('$2');")
	s = reImpNamed.ReplaceAllStringFunc(s, func(m string) string {
		g := reImpNamed.FindStringSubmatch(m)
		return "const {" + fixAs(g[1]) + "} = require('" + g[2] + "');"
	})
	s = reImpDefault.ReplaceAllString(s, "const $1 = require('$2');")
	s = reImpBare.ReplaceAllString(s, "require('$1');")
	s = reExpDefault.ReplaceAllString(s, "module.exports = ")
	s = reExpDecl.ReplaceAllString(s, "$1 ") // strip `export `, keep the declaration
	s = reExpList.ReplaceAllString(s, "")    // drop bare `export { … }` lists
	return s
}

// transpile converts TypeScript / JSX / modern-or-ESM JavaScript into the
// CommonJS ES2018 dialect goja can execute. esbuild only *parses and rewrites*
// the source - it never runs it - so this stays safe for untrusted input. It
// also normalizes syntax goja doesn't accept (ESM import/export, newer
// constructs), which makes the loader far more robust against real packages.
func (r *Runtime) transpile(abs string, src []byte) string {
	loader := api.LoaderJS
	switch strings.ToLower(filepath.Ext(abs)) {
	case ".ts", ".cts", ".mts":
		loader = api.LoaderTS
	case ".tsx":
		loader = api.LoaderTSX
	case ".jsx":
		loader = api.LoaderJSX
	}
	// Target ES2016. goja can't parse async generators (`async function*`) or
	// `for await…of` (ES2018), so those must be down-leveled. ES2017 would do that
	// too, BUT when esbuild lowers an async generator at ES2017 it moves `super.x`
	// into a nested plain `function*()` without capturing it (super is illegal
	// there) - goja then rejects "'super' keyword unexpected here" (hit in next's
	// route-matcher). Dropping to ES2016 also lowers async/await, which makes
	// esbuild route every `super` through its __superGet capture helper, so super
	// survives the move. goja runs the resulting generator/promise code fine.
	opts := api.TransformOptions{
		Loader:     loader,
		Format:     api.FormatCommonJS, // → require()/module.exports, matches our wrapper
		Platform:   api.PlatformNode,
		Target:     api.ES2016,
		Sourcefile: abs,
		LogLevel:   api.LogLevelSilent,
		// goja's parser rejects several constructs esbuild would otherwise pass
		// through unchanged. Mark them unsupported so esbuild down-converts them:
		//  - dynamic-import: `await import('x')` → require-based Promise; goja
		//    treats a bare `import` as a reserved word ("Unexpected reserved word",
		//    seen in zod/vitest test files).
		//  - import-meta: `import.meta` has no goja equivalent.
		Supported: map[string]bool{
			"dynamic-import": false,
			"import-meta":    false,
		},
	}
	res := api.Transform(string(src), opts)
	if len(res.Errors) > 0 {
		// Top-level await (modern ESM) can't be lowered to CommonJS, so esbuild errors
		// - and goja can't run TLA in a script either. Re-transpile keeping TLA (which
		// still converts import/export → require/module.exports), then wrap the body in
		// an async IIFE so `await` is legal and goja runs it. Side effects (the payload)
		// still detonate; only the export timing changes.
		if hasTopLevelAwaitError(res.Errors) {
			// Rewrite ESM imports → require (esbuild can't, with TLA present), wrap the
			// body in an async IIFE so the top-level `await` becomes legal, then let
			// esbuild lower the rest (async/await, dynamic import, TS types).
			wrapped := "(async()=>{\n" + esmImportsToRequire(stripShebang(string(src))) + "\n})().catch(function(){});"
			if r2 := api.Transform(wrapped, opts); len(r2.Errors) == 0 {
				return stripShebang(string(r2.Code))
			}
		}
		r.tr.Note(trace.CatModule, "transpile-error", res.Errors[0].Text, abs)
		return stripShebang(string(src)) // fall back to raw; goja may still parse it
	}
	// esbuild preserves a leading shebang (#!/usr/bin/env node) in its output, but
	// goja's parser rejects "#!" as an illegal token. Node strips the shebang from
	// CommonJS entry files before compiling; do the same so bin/* scripts (semver,
	// many CLIs) load instead of failing with "Unexpected token ILLEGAL".
	return stripShebang(string(res.Code))
}

// hasTopLevelAwaitError reports whether any esbuild error is the top-level-await
// "not available in the configured target" message (the trigger for the async-IIFE
// wrap retry).
func hasTopLevelAwaitError(errs []api.Message) bool {
	for _, e := range errs {
		if strings.Contains(strings.ToLower(e.Text), "top-level await") {
			return true
		}
	}
	return false
}

// stripShebang removes a leading "#!..." line (an executable-script hashbang),
// which is valid in a Node entry file but not accepted by goja's parser.
func stripShebang(s string) string {
	if strings.HasPrefix(s, "#!") {
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			return s[nl+1:] // drop the shebang line, keep line count via the newline
		}
		return ""
	}
	return s
}
