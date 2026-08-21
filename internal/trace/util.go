package trace

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// evLimit caps how many evidence items a reason carries, so a sample with
// hundreds of eval calls doesn't bury the report. The overflow is summarized.
const evLimit = 12

// isCtrl reports whether r is a terminal control character: a C0 control
// (0x00-0x1F), DEL (0x7F), or a C1 control (0x80-0x9F).
func isCtrl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// StripControl removes terminal control characters from s. The report includes
// attacker-controlled strings (package names, IOC values, decoded payloads,
// dependency names); printed raw they could carry ANSI escape sequences that
// rewrite the analyst's terminal - e.g. `\x1b[2J\x1b[H` to clear the screen and
// spoof a clean verdict. Printable UTF-8 is preserved. The JSON report is
// unaffected (encoding/json already escapes control bytes).
func StripControl(s string) string {
	if !strings.ContainsFunc(s, isCtrl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isCtrl(r) {
			return -1
		}
		return r
	}, s)
}

// clip trims s and bounds it to n runes, appending an ellipsis when truncated.
func clip(s string, n int) string {
	s = StripControl(strings.TrimSpace(s))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// clipList dedupes (preserving order), drops empties, and caps to evLimit,
// replacing the tail with a "… (N more)" summary line.
func clipList(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it == "" || seen[it] {
			continue
		}
		seen[it] = true
		out = append(out, it)
	}
	if len(out) > evLimit {
		extra := len(out) - evLimit
		out = append(out[:evLimit:evLimit], fmt.Sprintf("… (%d more)", extra))
	}
	return out
}

// summary renders an event as a one-line, length-bounded evidence string,
// attributed to its source package when that isn't the root.
func (e Event) summary() string {
	s := e.Op
	if len(e.Args) > 0 {
		s += ": " + strings.Join(e.Args, " ")
	}
	if e.Note != "" {
		s += " - " + e.Note
	}
	if e.Source != "" && e.Source != "(root)" {
		s = "[" + e.Source + "] " + s
	}
	return clip(strings.Join(strings.Fields(s), " "), 240)
}

// firstArg returns the first real argument of a command line, skipping leading
// VAR=value environment assignments and surrounding quotes.
func firstArg(cmd string) string {
	for _, tok := range strings.Fields(cmd) {
		if i := strings.IndexByte(tok, '='); i > 0 && isEnvAssign(tok[:i]) {
			continue // skip `NODE_ENV=production`-style prefixes
		}
		return strings.Trim(tok, `"'`)
	}
	return ""
}

// leadingBinary returns the executable a command line invokes (path stripped).
func leadingBinary(cmd string) string {
	tok := firstArg(cmd)
	if i := strings.LastIndexAny(tok, `/\`); i >= 0 {
		tok = tok[i+1:]
	}
	return strings.ToLower(tok)
}

func isEnvAssign(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// procCommand reconstructs the command string an event spawned.
func procCommand(e Event) string {
	if len(e.Args) > 0 {
		return strings.Join(e.Args, " ")
	}
	return e.Note
}

// matchAnyCommand returns commands whose raw OR deobfuscated form matches re, as
// evidence (the raw command is reported so the report stays readable). Scanning the
// deobfuscated view defeats the string-splitting/encoding tricks malware uses to
// slip a reverse shell or download cradle past a substring match.
func matchAnyCommand(cmds map[string]struct{}, re *regexp.Regexp) []string {
	var out []string
	for c := range cmds {
		if re.MatchString(c) || re.MatchString(deobfuscateViews(c)) {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// matchContains returns members of set whose lower-cased form contains any
// marker, as evidence.
func matchContains(set map[string]struct{}, markers []string) []string {
	var out []string
	for v := range set {
		lv := strings.ToLower(v)
		for _, m := range markers {
			if strings.Contains(lv, m) {
				out = append(out, v)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// truncField collapses whitespace in v and bounds it to n runes, for embedding a
// raw command/blob in evidence without flooding the report.
func truncField(v string, n int) string {
	v = StripControl(strings.Join(strings.Fields(v), " "))
	if len(v) > n {
		v = v[:n] + "…"
	}
	return v
}
