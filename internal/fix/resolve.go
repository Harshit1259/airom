package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Online describes what the registry and OSV said about a Target's FIX TO
// version, once Resolve has asked them.
type Online string

const (
	// OnlineUnchecked: Resolve did not run, or this ecosystem has no registry
	// wired. The advisory's own fixed version stands, unproven.
	OnlineUnchecked Online = ""
	// OnlineClean: the version is a real release on the registry and OSV
	// reports no advisory against it.
	OnlineClean Online = "clean"
	// OnlineStillVulnerable: the version is real and clears the advisories the
	// scan found, but OSV names others against it, and no newer release within
	// reach is clean either.
	OnlineStillVulnerable Online = "still-vulnerable"
	// OnlineFailed: the registry or OSV could not be reached for this package.
	OnlineFailed Online = "failed"
)

// The live endpoints. Variables, not constants, so tests point them at an
// httptest server.
var (
	OSVBatchEndpoint = "https://api.osv.dev/v1/querybatch"
	PyPIBase         = "https://pypi.org/pypi"
	NPMBase          = "https://registry.npmjs.org"
	GoProxyBase      = "https://proxy.golang.org"
	CratesBase       = "https://crates.io/api/v1/crates"
)

// maxCandidates caps how many releases above the advisory floor are checked
// against OSV for one package. One batch request covers all of them (OSV takes
// up to 1000); the cap keeps it bounded for a package with thousands of
// releases, while still reaching the newer major lines Alternatives draws on.
const maxCandidates = 300

// ResolveOptions configures Resolve.
type ResolveOptions struct {
	HTTP        Doer // default: an http.Client with a 20s timeout
	Concurrency int  // packages resolved at once; default 6
}

// Doer is the subset of *http.Client Resolve needs.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// osvEcosystem maps a purl type onto the ecosystem name OSV's query API takes.
var osvEcosystem = map[string]string{
	"pypi": "PyPI", "npm": "npm", "golang": "Go", "cargo": "crates.io",
	"maven": "Maven", "nuget": "NuGet",
}

// Resolve asks the internet which version each target should actually move to.
//
// The advisory's "fixed" field answers one narrow question: the first release
// that is no longer affected by THAT advisory. It does not say the release
// exists on the registry today (it may be yanked, or only ever tagged in git),
// and it does not say the release is clean — a version that clears the
// advisories found on 0.0.310 can carry newer ones of its own, which the scan
// never saw because it only asked about 0.0.310. Bumping to it trades one
// known advisory for another.
//
// So for every target this lists the real releases from the package's registry,
// keeps the stable ones at or above the advisory floor, asks OSV about all of
// them in one batch, and picks the LOWEST one with no advisory at all: the
// smallest upgrade that actually ends the problem. When none in reach is clean
// the floor (or the first real release above it) stands and the row says so.
//
// A failure for one package never fails the others; that row keeps the advisory
// version and is marked OnlineFailed with the reason.
func Resolve(ctx context.Context, targets []Target, opts ResolveOptions) []Target {
	client := opts.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 6
	}

	out := append([]Target(nil), targets...)
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		sem <- struct{}{}
		go func(t *Target) {
			defer wg.Done()
			defer func() { <-sem }()
			resolveOne(ctx, client, t)
		}(&out[i])
	}
	wg.Wait()
	return out
}

func resolveOne(ctx context.Context, client Doer, t *Target) {
	t.Advisory = t.Fixed
	eco, ok := osvEcosystem[t.Ecosystem]
	if !ok {
		t.Note = "ecosystem not checked online"
		return
	}
	releases, err := registryVersions(ctx, client, t.Ecosystem, t.Package)
	if err != nil {
		t.Online, t.Note = OnlineFailed, "registry lookup failed: "+err.Error()
		return
	}
	if len(releases) == 0 {
		t.Online, t.Note = OnlineFailed, "registry lists no stable releases"
		return
	}
	t.Latest = releases[len(releases)-1]

	floor, fok := parseVersion(t.Fixed)
	cur, cok := parseVersion(t.Current)
	var cands []string
	for _, r := range releases {
		rv, ok := parseVersion(r)
		if !ok {
			continue
		}
		if fok && compareVersions(rv, floor) < 0 {
			continue
		}
		if cok && compareVersions(rv, cur) <= 0 {
			continue
		}
		cands = append(cands, r)
	}
	if len(cands) == 0 {
		t.Online = OnlineFailed
		t.Note = fmt.Sprintf("no release at or above %s is published (latest is %s)", t.Fixed, t.Latest)
		return
	}
	// The newest release is always checked, even past the cap: it is the
	// answer when everything between is vulnerable too.
	if len(cands) > maxCandidates {
		cands = append(cands[:maxCandidates-1:maxCandidates-1], cands[len(cands)-1])
	}

	counts, err := osvCounts(ctx, client, eco, t.Package, cands)
	if err != nil {
		t.Online, t.Note = OnlineFailed, "OSV lookup failed: "+err.Error()
		// The floor still stands if the registry has it.
		t.Fixed = cands[0]
		t.Major = crossesMajor(t.Current, t.Fixed)
		return
	}
	for i, c := range cands {
		if counts[i] == 0 {
			t.Fixed, t.Online = c, OnlineClean
			if c != t.Advisory {
				t.Note = fmt.Sprintf("advisory says %s; first release with no known advisory is %s", t.Advisory, c)
			}
			t.Major = crossesMajor(t.Current, t.Fixed)
			t.Alternatives = fallbacks(cands[i+1:], counts[i+1:], c)
			return
		}
	}
	// Nothing in reach is clean. Move to the lowest real release that clears
	// what the scan found, and say how much is still open there.
	t.Fixed, t.Online = cands[0], OnlineStillVulnerable
	t.Note = fmt.Sprintf("%s clears the advisories found, but OSV still lists %d against it; no release up to %s is clean",
		cands[0], counts[0], cands[len(cands)-1])
	t.Major = crossesMajor(t.Current, t.Fixed)
}

// fallbacks returns the clean releases an upgrade tries, in order, when the
// package manager will not accept chosen alongside the rest of the project:
// the newest clean release on chosen's own line, then the lowest and the newest
// clean release of each newer line. Capped, because each attempt is a real
// install.
//
// Lowest AND newest per line, because neither alone is enough. The lowest is
// the smallest move; but a single release can be broken on its own —
// langchain 1.2.3 pins @langchain/core 1.1.8 while its own dependencies need
// ^1.1.48 — and the newest on the same line is where that gets repaired.
func fallbacks(cands []string, counts []int, chosen string) []string {
	const maxFallbacks = 6
	cv, _ := parseVersion(chosen)
	type span struct{ lo, hi string }
	lines := map[[2]int]*span{}
	var order [][2]int
	for i, c := range cands {
		if counts[i] != 0 {
			continue
		}
		v, ok := parseVersion(c)
		if !ok {
			continue
		}
		l := compatLine(v)
		if lines[l] == nil {
			lines[l] = &span{lo: c}
			order = append(order, l)
		}
		lines[l].hi = c
	}
	var out []string
	add := func(v string) {
		if v != "" && v != chosen && len(out) < maxFallbacks && (len(out) == 0 || out[len(out)-1] != v) {
			out = append(out, v)
		}
	}
	for _, l := range order {
		sp := lines[l]
		if l == compatLine(cv) {
			add(sp.hi)
			continue
		}
		add(sp.lo)
		add(sp.hi)
	}
	return out
}

// registryVersions returns the package's stable, non-yanked releases in
// ascending version order.
func registryVersions(ctx context.Context, client Doer, eco, name string) ([]string, error) {
	var vs []string
	switch eco {
	case "pypi":
		var doc struct {
			Releases map[string][]struct {
				Yanked bool `json:"yanked"`
			} `json:"releases"`
		}
		if err := getJSON(ctx, client, PyPIBase+"/"+url.PathEscape(name)+"/json", nil, &doc); err != nil {
			return nil, err
		}
		for v, files := range doc.Releases {
			if len(files) == 0 {
				continue // a release with no files cannot be installed
			}
			yanked := true
			for _, f := range files {
				yanked = yanked && f.Yanked
			}
			if !yanked {
				vs = append(vs, v)
			}
		}
	case "npm":
		var doc struct {
			Versions map[string]struct {
				Deprecated json.RawMessage `json:"deprecated"`
			} `json:"versions"`
		}
		// The abbreviated metadata document: the full one for a busy package
		// is tens of megabytes of READMEs nobody asked for.
		hdr := map[string]string{"Accept": "application/vnd.npm.install-v1+json"}
		if err := getJSON(ctx, client, NPMBase+"/"+npmEscape(name), hdr, &doc); err != nil {
			return nil, err
		}
		for v, meta := range doc.Versions {
			if len(meta.Deprecated) > 0 && string(meta.Deprecated) != "false" {
				continue
			}
			vs = append(vs, v)
		}
	case "golang":
		body, err := get(ctx, client, GoProxyBase+"/"+goEscape(name)+"/@v/list", nil)
		if err != nil {
			return nil, err
		}
		vs = append(vs, strings.Fields(string(body))...)
	case "cargo":
		var doc struct {
			Versions []struct {
				Num    string `json:"num"`
				Yanked bool   `json:"yanked"`
			} `json:"versions"`
		}
		// crates.io refuses requests that do not identify themselves.
		hdr := map[string]string{"User-Agent": "airom (https://github.com/airomhq/airom)"}
		if err := getJSON(ctx, client, CratesBase+"/"+url.PathEscape(name)+"/versions", hdr, &doc); err != nil {
			return nil, err
		}
		for _, v := range doc.Versions {
			if !v.Yanked {
				vs = append(vs, v.Num)
			}
		}
	default:
		return nil, fmt.Errorf("no registry wired for %s", eco)
	}

	stable := vs[:0]
	for _, v := range vs {
		if isStable(v) {
			stable = append(stable, v)
		}
	}
	sort.SliceStable(stable, func(i, j int) bool {
		a, _ := parseVersion(stable[i])
		b, _ := parseVersion(stable[j])
		if c := compareVersions(a, b); c != 0 {
			return c < 0
		}
		return stable[i] < stable[j]
	})
	return stable, nil
}

// isStable rejects pre-releases. A fix that lands on 2.0.0rc1 or 3.1.0-beta.2
// is not something a remediation tool should install unasked: those are not
// the releases a maintainer stands behind.
func isStable(v string) bool {
	s := strings.TrimSuffix(strings.TrimPrefix(v, "v"), "+incompatible")
	// PyPI post-releases (1.2.3.post1) are stable re-uploads of a release.
	if i := strings.Index(s, ".post"); i > 0 && isDigits(s[i+5:]) {
		s = s[:i]
	}
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	return isDigits(strings.ReplaceAll(s, ".", ""))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// osvCounts asks OSV, in one batch, how many advisories name each version.
func osvCounts(ctx context.Context, client Doer, eco, name string, versions []string) ([]int, error) {
	type pkg struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type q struct {
		Package pkg    `json:"package"`
		Version string `json:"version"`
	}
	qs := make([]q, len(versions))
	for i, v := range versions {
		qs[i] = q{Package: pkg{Name: name, Ecosystem: eco}, Version: v}
	}
	body, _ := json.Marshal(map[string]any{"queries": qs})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, OSVBatchEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	data, err := do(client, req)
	if err != nil {
		return nil, err
	}
	var r struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	if len(r.Results) != len(versions) {
		return nil, fmt.Errorf("OSV answered %d of %d queries", len(r.Results), len(versions))
	}
	out := make([]int, len(versions))
	for i, res := range r.Results {
		out[i] = len(res.Vulns)
	}
	return out, nil
}

// CheckVersion reports how many OSV advisories name pkg@version. Used after an
// upgrade, to confirm the version that is now in place is the clean one.
func CheckVersion(ctx context.Context, client Doer, ecosystem, pkg, version string) (int, error) {
	eco, ok := osvEcosystem[ecosystem]
	if !ok {
		return 0, fmt.Errorf("no OSV ecosystem for %s", ecosystem)
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	n, err := osvCounts(ctx, client, eco, pkg, []string{version})
	if err != nil {
		return 0, err
	}
	return n[0], nil
}

func getJSON(ctx context.Context, client Doer, u string, hdr map[string]string, v any) error {
	data, err := get(ctx, client, u, hdr)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode %s: %w", u, err)
	}
	return nil
}

func get(ctx context.Context, client Doer, u string, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(client, req)
}

func do(client Doer, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: not found", req.URL.Host)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// npmEscape encodes a package name for the registry URL: a scoped name keeps
// its @ and has its slash escaped (@scope%2Fname).
func npmEscape(name string) string {
	if strings.HasPrefix(name, "@") {
		return "@" + url.PathEscape(name[1:]) // PathEscape turns the slash into %2F
	}
	return url.PathEscape(name)
}

// goEscape applies the module proxy's case encoding: every upper-case letter
// becomes "!" plus its lower-case form, because the proxy is served from
// case-insensitive file systems.
func goEscape(mod string) string {
	var b strings.Builder
	for _, r := range mod {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
