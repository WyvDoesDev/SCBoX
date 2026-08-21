// Package rules implements user-defined taint-analysis rules, loaded from YAML.
//
// A rule names taint SOURCES (env vars and/or file paths the sample reads,
// matched by glob) and SINKS (where a tainted value must show up to count:
// network egress, spawned commands, file writes). The sandbox watches the
// VALUE it hands back for every matching source; the verdict then checks
// whether that value - raw, or base64/hex encoded - reached one of the rule's
// sinks, which is direct proof of flow rather than a mere read+egress
// correlation. This mirrors the built-in credential-exfil taint (see
// trace.Tracer.WatchSecret) but with user-controlled sources, sinks, bait
// values, severity, and attribution.
package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"scbox/internal/third_party/yaml"
)

// Sink names a place a tainted value can land.
const (
	SinkNetwork = "network" // request URLs, bodies, headers, contacted hosts
	SinkCommand = "command" // spawned process command lines
	SinkFile    = "file"    // file writes (path or content)
)

var validSinks = map[string]bool{SinkNetwork: true, SinkCommand: true, SinkFile: true}

// severityWeights maps a rule severity to its verdict weight (the scale used by
// the built-in detectors: 60 alone crosses the malicious threshold, 30 the
// suspicious one).
var severityWeights = map[string]int{"low": 10, "suspicious": 30, "malicious": 60}

// Source is one taint origin within a rule. Exactly one of Env or File must be
// set.
type Source struct {
	// Env is a glob over environment variable NAMES (e.g. "CORP_*"). The value
	// the fake env returns for a matching variable is watched. If the name is
	// literal (no wildcard) and not already present in the fake env, it is
	// seeded - with Bait if given, otherwise a generated decoy - so a read
	// returns a watchable value.
	Env string `yaml:"env,omitempty" json:"env,omitempty"`
	// File is a glob over file paths the sample reads (e.g. "**/.corprc",
	// "~/.config/corp/*.json"). `*` does not cross `/`, `**` does, and a
	// leading `~` matches any home directory. A relative pattern is matched
	// against the end of the path. The content handed back for a matching read
	// is watched; if Bait is set it overrides the sandbox's generated content.
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	// Bait optionally fixes the decoy value/content served for this source.
	Bait string `yaml:"bait,omitempty" json:"bait,omitempty"`
}

// Rule is one user-defined taint rule.
type Rule struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Severity maps to a verdict weight: low=10, suspicious=30, malicious=60.
	// Default suspicious; Weight (1..100) overrides it when set.
	Severity string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	Weight   int      `yaml:"weight,omitempty" json:"weight,omitempty"`
	Sources  []Source `yaml:"sources" json:"sources"`
	// Sinks defaults to [network].
	Sinks []string `yaml:"sinks,omitempty" json:"sinks,omitempty"`
}

// file is the YAML document shape.
type file struct {
	Taint []Rule `yaml:"taint"`
}

// Load reads and validates a YAML rules file.
func Load(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rs, nil
}

// Parse decodes and validates YAML rule content.
func Parse(b []byte) ([]Rule, error) {
	var f file
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if len(f.Taint) == 0 {
		return nil, fmt.Errorf("no taint rules defined (expected a top-level `taint:` list)")
	}
	seen := map[string]bool{}
	for i := range f.Taint {
		r := &f.Taint[i]
		if err := r.validate(); err != nil {
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("#%d", i+1)
			}
			return nil, fmt.Errorf("rule %s: %w", name, err)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("rule %q: duplicate name", r.Name)
		}
		seen[r.Name] = true
	}
	return f.Taint, nil
}

// validate checks one rule and fills in defaults (severity, sinks).
func (r *Rule) validate() error {
	if r.Name == "" {
		return fmt.Errorf("missing name")
	}
	if r.Weight < 0 || r.Weight > 100 {
		return fmt.Errorf("weight must be 1..100, got %d", r.Weight)
	}
	if r.Severity == "" {
		r.Severity = "suspicious"
	}
	if _, ok := severityWeights[r.Severity]; !ok {
		return fmt.Errorf("severity must be low|suspicious|malicious, got %q", r.Severity)
	}
	if len(r.Sources) == 0 {
		return fmt.Errorf("needs at least one source")
	}
	for i, s := range r.Sources {
		switch {
		case s.Env == "" && s.File == "":
			return fmt.Errorf("source #%d: set `env:` or `file:`", i+1)
		case s.Env != "" && s.File != "":
			return fmt.Errorf("source #%d: set only one of `env:` / `file:`", i+1)
		}
		pat := s.Env + s.File
		if _, err := compileGlob(pat, s.File != ""); err != nil {
			return fmt.Errorf("source #%d: bad pattern %q: %w", i+1, pat, err)
		}
	}
	if len(r.Sinks) == 0 {
		r.Sinks = []string{SinkNetwork}
	}
	for _, s := range r.Sinks {
		if !validSinks[s] {
			return fmt.Errorf("sink must be network|command|file, got %q", s)
		}
	}
	return nil
}

// EffectiveWeight returns the verdict weight for this rule.
func (r *Rule) EffectiveWeight() int {
	if r.Weight > 0 {
		return r.Weight
	}
	return severityWeights[r.Severity]
}

// MatchesEnv reports whether the rule has an env source matching the variable
// name.
func (r *Rule) MatchesEnv(name string) bool {
	for _, s := range r.Sources {
		if s.Env != "" && matchGlob(s.Env, name, false) {
			return true
		}
	}
	return false
}

// MatchesFile reports whether the rule has a file source matching the path.
func (r *Rule) MatchesFile(path string) bool {
	for _, s := range r.Sources {
		if s.File != "" && matchGlob(s.File, path, true) {
			return true
		}
	}
	return false
}

// FileBait returns the configured bait content for the first file source
// matching path, if any.
func FileBait(rs []Rule, path string) (string, bool) {
	for _, r := range rs {
		for _, s := range r.Sources {
			if s.File != "" && s.Bait != "" && matchGlob(s.File, path, true) {
				return s.Bait, true
			}
		}
	}
	return "", false
}

// LiteralEnvName reports the pattern as a plain env-var name when it carries no
// glob metacharacters (so the sandbox can seed it into the fake env).
func LiteralEnvName(pattern string) (string, bool) {
	if strings.ContainsAny(pattern, "*?") {
		return "", false
	}
	return pattern, true
}

// --- glob matching ---

// reCache caches compiled glob patterns; rules survive gob serialization to the
// jailed worker as plain data, so compiled state lives here, not on the Rule.
var reCache sync.Map // pattern key -> *regexp.Regexp

// matchGlob matches s against a glob. For path globs `*` stops at `/`, `**`
// crosses it, a leading `~` matches any home directory, and a relative pattern
// anchors at the end of the path; for env-name globs `*` matches anything.
func matchGlob(pattern, s string, isPath bool) bool {
	re, err := compileGlob(pattern, isPath)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func compileGlob(pattern string, isPath bool) (*regexp.Regexp, error) {
	key := pattern
	if isPath {
		key = "p\x00" + pattern
	} else {
		key = "e\x00" + pattern
	}
	if v, ok := reCache.Load(key); ok {
		return v.(*regexp.Regexp), nil
	}
	var b strings.Builder
	b.WriteString("(?s)")
	p := pattern
	if isPath {
		switch {
		case strings.HasPrefix(p, "~"):
			b.WriteString(`^(?:/home/[^/]+|/root)`)
			p = strings.TrimPrefix(p, "~")
		case strings.HasPrefix(p, "/") || strings.HasPrefix(p, "**"):
			b.WriteString("^")
		default:
			// Relative pattern: match the tail of the path on a separator boundary.
			b.WriteString(`(?:^|/)`)
		}
	} else {
		b.WriteString("^")
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '*':
			if isPath {
				if i+1 < len(p) && p[i+1] == '*' {
					b.WriteString(".*")
					i++
				} else {
					b.WriteString("[^/]*")
				}
			} else {
				b.WriteString(".*")
			}
		case '?':
			if isPath {
				b.WriteString("[^/]")
			} else {
				b.WriteString(".")
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	reCache.Store(key, re)
	return re, nil
}
