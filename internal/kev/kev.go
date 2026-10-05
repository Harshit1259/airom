// Package kev is the known-exploited-vulnerability overlay: it marks the CVEs
// the CVE overlay already found that appear in CISA's Known Exploited
// Vulnerabilities catalog.
//
// It answers a question CVSS cannot. A CVSS score rates how bad exploitation
// WOULD be; KEV records that exploitation HAS happened. The two are orthogonal
// and routinely disagree — a medium-severity CVE under active exploitation is a
// more urgent problem than a critical nobody has ever used — so this overlay
// never rewrites Severity or Score. It attaches a dated record and leaves the
// weighing to the reader, or to `--fail-on cve:kev`.
//
// Like the model-lifecycle overlay and unlike the CVE overlay itself, the
// catalog is data rather than a query: embedded in the binary and refreshable
// through the signed airom-rules bundle. So this overlay adds no network
// round-trips of its own — it rides the ones the CVE overlay already made.
//
// That is not the same as working offline. It has nothing to mark unless the
// CVE overlay ran first, and that overlay needs the network, so under
// --offline there are no CVEs and therefore no exploitation status. The
// catalog being local buys reproducibility and zero extra requests, not
// offline operation.
//
// Two properties keep it honest:
//
//   - A CVE absent from the catalog gets NO record. That is "CISA does not list
//     it", not "not exploited" — and because CISA adds entries several times a
//     week, a stale catalog says it about CVEs it has never heard of.
//   - Which catalog answered is recorded in EnrichmentStats.CVE.KEVCatalog, so
//     a nil KEV on a vulnerability can be read: with a catalog named it means
//     not listed, with none it means nobody looked.
package kev

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/airomhq/airom/pkg/airom"
)

//go:embed catalog/*.yaml
var catalogFS embed.FS

// BundleDir is where a fetched rule bundle carries a KEV catalog, alongside the
// rule packs and the lifecycle catalogs. CISA publishes on its own cadence, not
// AIROM's release schedule, so `airom rules update` is the lever that refreshes
// it without a binary upgrade.
const BundleDir = "kev"

// SourceBuiltin and SourceBundle label where a catalog came from, so a scan can
// tell a user which lever actually refreshes it.
const (
	SourceBuiltin = "builtin"
	SourceBundle  = "bundle"
)

// StaleAfterDays is how long a catalog may go unrefreshed before the scan says
// so. CISA adds entries several times a week; a catalog nobody has refreshed in
// a month is missing exploitation that has already been published, and this
// overlay's failure direction is under-reporting.
const StaleAfterDays = 30

// catalogFile is the generated catalog as written on disk (tools/kev-gen).
type catalogFile struct {
	Source         string   `yaml:"source"`
	CatalogVersion string   `yaml:"catalogVersion"`
	Released       string   `yaml:"released"`
	Generated      string   `yaml:"generated"`
	Count          int      `yaml:"count"`
	Vulns          []record `yaml:"vulnerabilities"`
}

type record struct {
	ID         string `yaml:"id"`
	Added      string `yaml:"added"`
	Due        string `yaml:"due"`
	Ransomware bool   `yaml:"ransomware"`
}

// Catalog is the compiled lookup: upper-cased CVE id → record.
type Catalog struct {
	// Version is CISA's own catalog version, e.g. "2026.09.30".
	Version string
	// Released is the day CISA published it.
	Released airom.Date
	// Generated is the day tools/kev-gen transcribed it, which is what staleness
	// is measured from: a catalog is only as fresh as the last refresh.
	Generated airom.Date
	byID      map[string]airom.KEVRecord
}

// Len reports how many CVEs the catalog carries.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.byID)
}

// Lookup returns the record for a CVE id, if the catalog lists it. Matching is
// case-insensitive because advisory ids arrive in both cases from OSV aliases.
func (c *Catalog) Lookup(id string) (airom.KEVRecord, bool) {
	if c == nil || id == "" {
		return airom.KEVRecord{}, false
	}
	r, ok := c.byID[strings.ToUpper(strings.TrimSpace(id))]
	return r, ok
}

// Stale reports whether the catalog was generated more than StaleAfterDays ago,
// and by how many days, so the caller can say so rather than quietly trusting it.
func (c *Catalog) Stale(today airom.Date) (bool, int) {
	if c == nil || c.Generated.IsZero() {
		return false, 0
	}
	age := c.Generated.DaysUntil(today)
	return age > StaleAfterDays, age
}

// Load reads the catalog embedded in the binary — the offline floor.
func Load() (*Catalog, error) { return load(catalogFS, "catalog") }

// LoadBundle loads a KEV catalog from a fetched rule bundle. ok=false means the
// bundle carries none — an older bundle, or one published before this feature —
// which is not an error: the caller falls back to the embedded catalog.
func LoadBundle(bundle fs.FS) (c *Catalog, ok bool, err error) {
	if bundle == nil {
		return nil, false, nil
	}
	// Walk rather than glob: a catalog at kev/sub/cisa.yaml would otherwise be
	// invisible here while still being skipped by the rule walk — present in
	// the bundle, honored by nothing.
	var found bool
	_ = fs.WalkDir(bundle, BundleDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	if !found {
		return nil, false, nil
	}
	c, err = load(bundle, BundleDir)
	if err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// load compiles every *.yaml under dir into one catalog.
func load(fsys fs.FS, dir string) (*Catalog, error) {
	out := &Catalog{byID: map[string]airom.KEVRecord{}}
	var files []string
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read kev catalog: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("kev catalog: no .yaml files under %q", dir)
	}

	for _, p := range files {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		var cf catalogFile
		if err := yaml.Unmarshal(raw, &cf); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		if len(cf.Vulns) == 0 {
			return nil, fmt.Errorf("%s: catalog lists no vulnerabilities", p)
		}
		// A declared count that disagrees with the body means the file was
		// truncated or hand-edited. Silently accepting a short catalog is how
		// this overlay would under-report without anyone noticing.
		if cf.Count != 0 && cf.Count != len(cf.Vulns) {
			return nil, fmt.Errorf("%s: declares %d entries but carries %d", p, cf.Count, len(cf.Vulns))
		}
		released, err := parseDate(cf.Released)
		if err != nil {
			return nil, fmt.Errorf("%s: released: %w", p, err)
		}
		generated, err := parseDate(cf.Generated)
		if err != nil {
			return nil, fmt.Errorf("%s: generated: %w", p, err)
		}
		// Keep the OLDEST generated date across files: freshness is the weakest
		// link, not the strongest.
		if out.Generated.IsZero() || generated.Before(out.Generated) {
			out.Generated = generated
		}
		if out.Released.IsZero() || released.After(out.Released) {
			out.Released = released
			out.Version = cf.CatalogVersion
		}

		for _, r := range cf.Vulns {
			id := strings.ToUpper(strings.TrimSpace(r.ID))
			if id == "" {
				return nil, fmt.Errorf("%s: an entry has no id", p)
			}
			added, err := parseDate(r.Added)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: added: %w", p, id, err)
			}
			if added.IsZero() {
				return nil, fmt.Errorf("%s: %s: no added date", p, id)
			}
			var due airom.Date
			if r.Due != "" {
				if due, err = parseDate(r.Due); err != nil {
					return nil, fmt.Errorf("%s: %s: due: %w", p, id, err)
				}
			}
			out.byID[id] = airom.KEVRecord{
				Added: added, Due: due, Ransomware: r.Ransomware, Source: "cisa-kev",
			}
		}
	}
	return out, nil
}

// parseDate accepts "YYYY-MM-DD" and returns the zero Date for "".
func parseDate(s string) (airom.Date, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return airom.Date{}, nil
	}
	d, err := airom.ParseDate(s)
	if err != nil {
		return airom.Date{}, fmt.Errorf("%q is not YYYY-MM-DD", s)
	}
	return d, nil
}

// Enrich marks every vulnerability the catalog lists. It returns how many were
// marked. Vulnerabilities absent from the catalog are left untouched: there is
// no "not exploited" record to write, because CISA's silence is not a finding.
//
// Matching considers the advisory's aliases as well as its id: OSV reports
// GHSA ids for some ecosystems, and the CVE that CISA cataloged is then an
// alias rather than the primary id.
func Enrich(inv *airom.Inventory, c *Catalog) int {
	if inv == nil || c == nil || c.Len() == 0 {
		return 0
	}
	marked := 0
	for i := range inv.Components {
		vulns := inv.Components[i].Vulnerabilities
		for j := range vulns {
			if rec, ok := lookupAny(c, &vulns[j]); ok {
				vulns[j].KEV = &rec
				marked++
			}
		}
	}
	return marked
}

// lookupAny tries the advisory id, then each alias.
func lookupAny(c *Catalog, v *airom.Vulnerability) (airom.KEVRecord, bool) {
	if r, ok := c.Lookup(v.ID); ok {
		return r, true
	}
	for _, a := range v.Aliases {
		if r, ok := c.Lookup(a); ok {
			return r, true
		}
	}
	return airom.KEVRecord{}, false
}
