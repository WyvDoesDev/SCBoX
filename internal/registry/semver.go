package registry

import (
	"strconv"
	"strings"
)

// This is a deliberately small semver good enough for triage dependency
// resolution - it understands the ranges that appear in the overwhelming
// majority of package.json files (^, ~, comparators, x-ranges, OR) and falls
// back to "latest" when unsure. It is not a full npm-semver implementation.

type ver struct{ maj, min, pat int }

func parseVer(s string) (ver, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "=")
	// strip prerelease/build metadata
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	var v ver
	get := func(i int) (int, bool) {
		if i >= len(parts) {
			return 0, true
		}
		p := parts[i]
		if p == "x" || p == "X" || p == "*" {
			return 0, true
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	var ok bool
	if v.maj, ok = get(0); !ok {
		return v, false
	}
	if v.min, ok = get(1); !ok {
		return v, false
	}
	if v.pat, ok = get(2); !ok {
		return v, false
	}
	return v, true
}

func cmp(a, b ver) int {
	switch {
	case a.maj != b.maj:
		return sign(a.maj - b.maj)
	case a.min != b.min:
		return sign(a.min - b.min)
	default:
		return sign(a.pat - b.pat)
	}
}

func sign(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}

// compareSemver compares two concrete version strings.
func compareSemver(a, b string) int {
	va, _ := parseVer(a)
	vb, _ := parseVer(b)
	return cmp(va, vb)
}

// satisfies reports whether concrete version v meets npm range rng.
func satisfies(v, rng string) bool {
	rng = strings.TrimSpace(rng)
	if rng == "" || rng == "*" || rng == "latest" || rng == "x" {
		return true
	}
	cv, ok := parseVer(v)
	if !ok {
		return false
	}
	for _, orPart := range strings.Split(rng, "||") {
		if satisfiesAnd(cv, strings.Fields(orPart)) {
			return true
		}
	}
	return false
}

func satisfiesAnd(cv ver, comps []string) bool {
	if len(comps) == 0 {
		return true
	}
	for _, comp := range comps {
		if !satisfiesOne(cv, comp) {
			return false
		}
	}
	return true
}

func satisfiesOne(cv ver, comp string) bool {
	comp = strings.TrimSpace(comp)
	switch {
	case comp == "" || comp == "*" || comp == "x":
		return true
	case strings.HasPrefix(comp, "^"):
		base, ok := parseVer(comp[1:])
		if !ok {
			return true
		}
		if cmp(cv, base) < 0 {
			return false
		}
		if base.maj > 0 {
			return cv.maj == base.maj
		}
		if base.min > 0 {
			return cv.maj == 0 && cv.min == base.min
		}
		return cv.maj == 0 && cv.min == 0
	case strings.HasPrefix(comp, "~"):
		base, ok := parseVer(comp[1:])
		if !ok {
			return true
		}
		if cmp(cv, base) < 0 {
			return false
		}
		return cv.maj == base.maj && cv.min == base.min
	case strings.HasPrefix(comp, ">="):
		base, _ := parseVer(comp[2:])
		return cmp(cv, base) >= 0
	case strings.HasPrefix(comp, "<="):
		base, _ := parseVer(comp[2:])
		return cmp(cv, base) <= 0
	case strings.HasPrefix(comp, ">"):
		base, _ := parseVer(comp[1:])
		return cmp(cv, base) > 0
	case strings.HasPrefix(comp, "<"):
		base, _ := parseVer(comp[1:])
		return cmp(cv, base) < 0
	default:
		// Bare version or x-range: compare on the components actually specified.
		base, ok := parseVer(comp)
		if !ok {
			return true
		}
		parts := strings.Split(strings.TrimPrefix(comp, "="), ".")
		switch {
		case len(parts) >= 3 && !wild(parts[2]):
			return cmp(cv, base) == 0
		case len(parts) >= 2 && !wild(parts[1]):
			return cv.maj == base.maj && cv.min == base.min
		default:
			return cv.maj == base.maj
		}
	}
}

func wild(s string) bool { return s == "x" || s == "X" || s == "*" }
