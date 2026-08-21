// Package registry fetches npm package metadata and tarballs so the dependency
// tree can be materialized for analysis. It only ever downloads inert bytes -
// it never executes anything. Code is run exclusively inside the goja sandbox.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Client talks to an npm-compatible registry.
type Client struct {
	BaseURL  string
	HTTP     *http.Client
	CacheDir string
}

// NewClient returns a registry client. If cacheDir is empty, downloads are kept
// in memory only and nothing is persisted (the default - untrusted bytes never
// touch the host disk); a non-empty cacheDir opts into an on-disk tarball cache.
func NewClient(cacheDir string) *Client {
	// The resolver fires many concurrent requests at a single host
	// (registry.npmjs.org). Go's default transport keeps only 2 idle connections
	// per host, so a large dependency tree wastes most of its time re-running TLS
	// handshakes instead of reusing warm connections. Raise the idle pool so
	// connections are reused - but do NOT oversubscribe total connections: the
	// registry throttles aggressive clients, which makes things slower, not faster.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 128
	tr.MaxIdleConnsPerHost = 32
	tr.IdleConnTimeout = 90 * time.Second
	// Bound connection setup and time-to-first-byte tightly so a dead/slow server
	// fails fast, but do NOT cap the whole request at 60s: a few legitimately huge
	// tarballs (e.g. aws-sdk v2 is ~80MB) stream for longer than that and were
	// failing with "context deadline exceeded while reading body". The generous
	// overall ceiling still prevents an indefinite hang.
	tr.TLSHandshakeTimeout = 10 * time.Second
	tr.ResponseHeaderTimeout = 30 * time.Second
	return &Client{
		BaseURL:  "https://registry.npmjs.org",
		HTTP:     &http.Client{Timeout: 300 * time.Second, Transport: tr},
		CacheDir: cacheDir,
	}
}

// VersionMeta is the per-version metadata we care about.
type VersionMeta struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Dist                 struct {
		Tarball string `json:"tarball"`
		Shasum  string `json:"shasum"`
	} `json:"dist"`
}

type packument struct {
	DistTags map[string]string      `json:"dist-tags"`
	Versions map[string]VersionMeta `json:"versions"`
}

// Resolve picks a concrete version of name satisfying the npm range rng, and
// returns its metadata.
func (c *Client) Resolve(name, rng string) (VersionMeta, error) {
	pk, err := c.fetchPackument(name)
	if err != nil {
		return VersionMeta{}, err
	}
	// dist-tag (e.g. "latest", "next").
	if tag, ok := pk.DistTags[strings.TrimSpace(rng)]; ok {
		if vm, ok := pk.Versions[tag]; ok {
			return vm, nil
		}
	}
	if rng == "" || rng == "*" || rng == "latest" {
		if latest := pk.DistTags["latest"]; latest != "" {
			if vm, ok := pk.Versions[latest]; ok {
				return vm, nil
			}
		}
	}
	// Highest published version satisfying the range.
	best := ""
	for v := range pk.Versions {
		if !satisfies(v, rng) {
			continue
		}
		if best == "" || compareSemver(v, best) > 0 {
			best = v
		}
	}
	if best == "" {
		// Fall back to latest so analysis still proceeds.
		if latest := pk.DistTags["latest"]; latest != "" {
			if vm, ok := pk.Versions[latest]; ok {
				return vm, nil
			}
		}
		return VersionMeta{}, fmt.Errorf("no version of %s satisfies %q", name, rng)
	}
	return pk.Versions[best], nil
}

func (c *Client) fetchPackument(name string) (*packument, error) {
	// Scoped names (@scope/pkg) must keep the slash but be path-escaped as %2f
	// only for the scope separator per npm convention; the registry accepts the
	// raw slash, so use it directly.
	url := c.BaseURL + "/" + name
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata %s: %w", name, err)
	}
	// Request the abbreviated packument. It carries the same dist-tags / per-
	// version dependency + dist fields we parse, but omits READMEs and full
	// historical metadata - the full document for a popular package (e.g. @babel/*,
	// eslint, typescript) is many megabytes, which dominated resolution time.
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json, application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %s for %s", resp.Status, name)
	}
	var pk packument
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&pk); err != nil {
		return nil, fmt.Errorf("decode metadata %s: %w", name, err)
	}
	return &pk, nil
}

// cacheSlug maps an untrusted name/version into a flat token safe to embed in a
// cache filename: every character outside [A-Za-z0-9._-] (notably '/' and '\')
// becomes '-', so the token can contain no path separator and no traversal
// sequence. A leading '.' is also neutralized so the token can never form "." or
// ".." on its own.
func cacheSlug(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
			// keep
		case c == '.' && i != 0:
			// keep interior dots (real version separators) but not a leading one
		default:
			b[i] = '-'
		}
	}
	if len(b) == 0 {
		return "_"
	}
	return string(b)
}

// Download fetches a version's tarball and returns its bytes. By default the
// bytes are held only in memory; if CacheDir is set, they are also read from /
// written to an on-disk cache for speed across runs.
func (c *Client) Download(name string, vm VersionMeta) ([]byte, error) {
	if vm.Dist.Tarball == "" {
		return nil, fmt.Errorf("%s@%s has no tarball", name, vm.Version)
	}
	var dest string
	if c.CacheDir != "" {
		if err := os.MkdirAll(c.CacheDir, 0o755); err != nil {
			return nil, err
		}
		// name and vm.Version both originate from untrusted registry JSON. A
		// version like "../../../../tmp/evil" would survive filepath.Join (which
		// cleans the path) and let a malicious packument write tarball bytes
		// outside CacheDir. Reduce both to a flat, separator-free slug so the
		// result can only ever be a single file directly inside CacheDir.
		dest = filepath.Join(c.CacheDir, cacheSlug(name)+"-"+cacheSlug(vm.Version)+".tgz")
		if data, err := os.ReadFile(dest); err == nil && len(data) > 0 {
			return data, nil // cached
		}
	}
	resp, err := c.HTTP.Get(vm.Dist.Tarball)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", vm.Dist.Tarball, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tarball fetch returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	if dest != "" {
		// Best-effort cache write; a failure here must not fail the analysis.
		_ = os.WriteFile(dest, data, 0o644)
	}
	return data, nil
}
