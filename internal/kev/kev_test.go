package kev

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/airomhq/airom/pkg/airom"
)

// smallCatalog is a hand-written stand-in for the 1730-entry generated file, so
// these tests assert behavior rather than today's CISA contents.
const smallCatalog = `
source: https://example.test/kev.json
catalogVersion: "2026.09.30"
released: 2026-09-30
generated: 2026-09-30
count: 3
vulnerabilities:
  - id: CVE-2021-44228
    added: 2021-12-10
    due: 2021-12-24
    ransomware: true
  - id: CVE-2024-0001
    added: 2024-01-02
  - id: CVE-2026-64849
    added: 2026-08-19
    due: 2026-09-02
`

func testFS(t *testing.T, body string) fstest.MapFS {
	t.Helper()
	return fstest.MapFS{"kev/cisa.yaml": &fstest.MapFile{Data: []byte(body)}}
}

func loadSmall(t *testing.T) *Catalog {
	t.Helper()
	c, err := load(testFS(t, smallCatalog), "kev")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return c
}

// TestEmbeddedCatalogLoads compiles the real generated catalog exactly as the
// binary does at startup. A malformed or truncated regeneration fails here.
func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("embedded KEV catalog does not load: %v", err)
	}
	if c.Len() < 1000 {
		t.Errorf("catalog carries %d entries; CISA has published well over a thousand, so this looks truncated", c.Len())
	}
	if c.Version == "" || c.Released.IsZero() || c.Generated.IsZero() {
		t.Errorf("catalog provenance incomplete: version=%q released=%v generated=%v", c.Version, c.Released, c.Generated)
	}
}

// TestLookupIsCaseInsensitiveAndTrimmed: advisory ids arrive from OSV in both
// cases and occasionally padded, and a lookup miss here reads as "CISA does not
// list this", which is the wrong answer to give quietly.
func TestLookupIsCaseInsensitiveAndTrimmed(t *testing.T) {
	c := loadSmall(t)
	for _, id := range []string{"CVE-2021-44228", "cve-2021-44228", "  CVE-2021-44228  "} {
		if _, ok := c.Lookup(id); !ok {
			t.Errorf("Lookup(%q) missed", id)
		}
	}
	if _, ok := c.Lookup("CVE-1999-9999"); ok {
		t.Error("Lookup returned a record for a CVE the catalog does not list")
	}
	if _, ok := c.Lookup(""); ok {
		t.Error("Lookup(\"\") returned a record")
	}
}

// TestRecordCarriesCISAFields: the dates and the ransomware flag are the whole
// point — a record with no dates is indistinguishable from a bare membership
// test, which is not what CISA publishes.
func TestRecordCarriesCISAFields(t *testing.T) {
	c := loadSmall(t)
	r, ok := c.Lookup("CVE-2021-44228")
	if !ok {
		t.Fatal("CVE-2021-44228 missing")
	}
	if got := r.Added.String(); got != "2021-12-10" {
		t.Errorf("added = %s, want 2021-12-10", got)
	}
	if got := r.Due.String(); got != "2021-12-24" {
		t.Errorf("due = %s, want 2021-12-24", got)
	}
	if !r.Ransomware {
		t.Error("ransomware = false, want true")
	}
	if r.Source != "cisa-kev" {
		t.Errorf("source = %q, want cisa-kev", r.Source)
	}
	// An entry with no dueDate must load, with a zero Due rather than an error:
	// CISA does not set a deadline for every entry.
	r2, ok := c.Lookup("CVE-2024-0001")
	if !ok {
		t.Fatal("CVE-2024-0001 missing")
	}
	if !r2.Due.IsZero() {
		t.Errorf("due = %v, want zero for an entry with no dueDate", r2.Due)
	}
	if r2.Ransomware {
		t.Error("ransomware = true for an entry that does not declare it")
	}
}

// TestEnrichMarksOnlyListedCVEs: absence must stay absence. Writing a "not
// exploited" record would turn CISA's silence into a claim.
func TestEnrichMarksOnlyListedCVEs(t *testing.T) {
	inv := &airom.Inventory{Components: []airom.Component{{
		ID: "airom:1", Name: "mlflow", Kind: airom.KindFramework,
		Vulnerabilities: []airom.Vulnerability{
			{ID: "CVE-2026-64849", Severity: airom.VulnCritical},
			{ID: "CVE-1999-9999", Severity: airom.VulnHigh},
		},
	}}}
	if n := Enrich(inv, loadSmall(t)); n != 1 {
		t.Fatalf("marked %d, want 1", n)
	}
	v := inv.Components[0].Vulnerabilities
	if v[0].KEV == nil {
		t.Error("listed CVE was not marked")
	}
	if v[1].KEV != nil {
		t.Error("unlisted CVE was marked; CISA's silence is not a finding")
	}
}

// TestEnrichMatchesThroughAliases: OSV reports GHSA ids for some ecosystems, so
// the CVE CISA cataloged is an alias rather than the primary id. Missing that
// would under-report exploitation on exactly the advisories OSV normalizes.
func TestEnrichMatchesThroughAliases(t *testing.T) {
	inv := &airom.Inventory{Components: []airom.Component{{
		ID: "airom:1", Name: "log4j-ish", Kind: airom.KindLibrary,
		Vulnerabilities: []airom.Vulnerability{{
			ID:      "GHSA-jfh8-c2jp-5v3q",
			Aliases: []string{"CVE-2021-44228"},
		}},
	}}}
	if n := Enrich(inv, loadSmall(t)); n != 1 {
		t.Fatalf("marked %d, want 1 (match should fall through to the alias)", n)
	}
	if inv.Components[0].Vulnerabilities[0].KEV == nil {
		t.Error("advisory whose CVE alias is cataloged was not marked")
	}
}

// TestEnrichNeverRewritesSeverity: KEV and CVSS are orthogonal axes. Folding
// one into the other would invent a score CISA never published.
func TestEnrichNeverRewritesSeverity(t *testing.T) {
	inv := &airom.Inventory{Components: []airom.Component{{
		ID: "airom:1", Name: "x",
		Vulnerabilities: []airom.Vulnerability{
			{ID: "CVE-2026-64849", Severity: airom.VulnMedium, Score: 5.4},
		},
	}}}
	Enrich(inv, loadSmall(t))
	v := inv.Components[0].Vulnerabilities[0]
	if v.Severity != airom.VulnMedium || v.Score != 5.4 {
		t.Errorf("severity/score changed to %s/%v; KEV must not rewrite them", v.Severity, v.Score)
	}
	if v.KEV == nil {
		t.Error("the record itself was not attached")
	}
}

// TestEnrichNilSafe: an overlay that panics on an empty scan is worse than one
// that reports nothing.
func TestEnrichNilSafe(t *testing.T) {
	if n := Enrich(nil, loadSmall(t)); n != 0 {
		t.Errorf("Enrich(nil inventory) = %d", n)
	}
	if n := Enrich(&airom.Inventory{}, nil); n != 0 {
		t.Errorf("Enrich(nil catalog) = %d", n)
	}
	var empty Catalog
	if n := Enrich(&airom.Inventory{}, &empty); n != 0 {
		t.Errorf("Enrich(empty catalog) = %d", n)
	}
}

// TestLoadRejectsTruncatedCatalog: a count that disagrees with the body means
// the file was cut short or hand-edited. Accepting it silently shrinks the
// catalog, and this overlay's failure direction is under-reporting.
func TestLoadRejectsTruncatedCatalog(t *testing.T) {
	body := strings.Replace(smallCatalog, "count: 3", "count: 99", 1)
	if _, err := load(testFS(t, body), "kev"); err == nil {
		t.Fatal("a catalog declaring 99 entries and carrying 3 was accepted")
	} else if !strings.Contains(err.Error(), "declares 99") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestLoadRejectsMalformedRecords: every record is a transcription, so a bad
// date is a transcription error and must fail loudly rather than load as zero.
func TestLoadRejectsMalformedRecords(t *testing.T) {
	for name, body := range map[string]string{
		"no id":        strings.Replace(smallCatalog, "  - id: CVE-2024-0001", "  - id: \"\"", 1),
		"bad added":    strings.Replace(smallCatalog, "added: 2024-01-02", "added: Jan 2 2024", 1),
		"bad due":      strings.Replace(smallCatalog, "due: 2021-12-24", "due: soon", 1),
		"no entries":   "source: x\nreleased: 2026-09-30\ngenerated: 2026-09-30\nvulnerabilities: []\n",
		"bad released": strings.Replace(smallCatalog, "released: 2026-09-30", "released: 2026-13-45", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(testFS(t, body), "kev"); err == nil {
				t.Error("malformed catalog was accepted")
			}
		})
	}
}

// TestStale: CISA adds entries several times a week, so an old catalog is
// silently missing exploitation that is already public. The scan says so.
func TestStale(t *testing.T) {
	c := loadSmall(t)
	fresh := c.Generated.AddDays(StaleAfterDays)
	if stale, _ := c.Stale(fresh); stale {
		t.Error("a catalog exactly at the threshold is not yet stale")
	}
	old := c.Generated.AddDays(StaleAfterDays + 1)
	stale, age := c.Stale(old)
	if !stale || age != StaleAfterDays+1 {
		t.Errorf("Stale = %v, age %d; want true, %d", stale, age, StaleAfterDays+1)
	}
	var nilCat *Catalog
	if stale, _ := nilCat.Stale(fresh); stale {
		t.Error("a nil catalog reported stale")
	}
}

// TestLoadBundleAbsentIsNotAnError: a bundle published before this feature
// carries no kev/ directory, and must fall back to the embedded catalog rather
// than cost the user the overlay.
func TestLoadBundleAbsentIsNotAnError(t *testing.T) {
	c, ok, err := LoadBundle(fstest.MapFS{"models/openai.yaml": &fstest.MapFile{Data: []byte("name: x\n")}})
	if err != nil || ok || c != nil {
		t.Fatalf("LoadBundle(no kev dir) = %v, %v, %v; want nil, false, nil", c, ok, err)
	}
	if c, ok, err := LoadBundle(nil); err != nil || ok || c != nil {
		t.Fatalf("LoadBundle(nil) = %v, %v, %v; want nil, false, nil", c, ok, err)
	}
}

// TestLoadBundleFindsNestedCatalog: the rule walk skips the whole kev/ subtree,
// so a catalog one directory down would be present in the bundle and honored by
// nothing if this used a flat glob.
func TestLoadBundleFindsNestedCatalog(t *testing.T) {
	fsys := fstest.MapFS{"kev/sub/cisa.yaml": &fstest.MapFile{Data: []byte(smallCatalog)}}
	c, ok, err := LoadBundle(fsys)
	if err != nil || !ok {
		t.Fatalf("LoadBundle(nested) = %v, %v", ok, err)
	}
	if c.Len() != 3 {
		t.Errorf("loaded %d entries, want 3", c.Len())
	}
}
