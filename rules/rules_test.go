package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/ruleengine"
	"github.com/airomhq/airom/internal/ruleengine/ruletest"
)

// categories are the embedded rule-pack directories.
var categories = []string{
	"models", "embeddings", "frameworks", "vectordb",
	"infra", "params", "prompts", "datasets", "security",
}

// TestEmbeddedRulesetLoads compiles the ENTIRE embedded set exactly as the
// binary does at startup: global ID uniqueness, the full lint contract, and
// the Aho-Corasick build. A single invalid rule fails here (and would abort
// the real binary).
func TestEmbeddedRulesetLoads(t *testing.T) {
	rs, err := ruleengine.Load(FS(), nil, "", nil, os.ReadFile)
	if err != nil {
		t.Fatalf("embedded ruleset does not load: %v", err)
	}
	if _, err := ruleengine.Compile(rs); err != nil {
		t.Fatalf("embedded ruleset does not compile: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("embedded ruleset is empty")
	}
	t.Logf("embedded ruleset: %d rules across %d categories", len(rs.Rules), len(categories))
}

// TestEmbeddedPackFixtures runs every pack against its annotated fixtures
// and enforces the ≥1-positive-and-≥1-negative-per-rule contract
// (docs/rule-schema.md item 10).
func TestEmbeddedPackFixtures(t *testing.T) {
	packs := discoverPacks(t)
	if len(packs) == 0 {
		t.Fatal("no rule packs found")
	}
	for _, pack := range packs {
		t.Run(pack.rel, func(t *testing.T) {
			fixturesDir := filepath.Join(pack.dir, "testdata", pack.stem)
			if _, err := os.Stat(fixturesDir); err != nil {
				t.Fatalf("pack %s has no fixtures at %s (every rule needs positive+negative fixtures)", pack.rel, fixturesDir)
			}
			report, err := ruletest.RunPackFile(pack.path, fixturesDir)
			if err != nil {
				t.Fatalf("run pack: %v", err)
			}
			for _, f := range report.Failures {
				t.Errorf("%s:%d %s: %s", f.File, f.Line, f.RuleID, f.Reason)
			}
			for _, id := range report.RulesMissingPositive {
				t.Errorf("rule %s: no positive fixture (# airom: %s)", id, id)
			}
			for _, id := range report.RulesMissingNegative {
				t.Errorf("rule %s: no negative fixture (# airom-ok: %s)", id, id)
			}
		})
	}
}

type packInfo struct {
	path, dir, rel, stem string
}

func discoverPacks(t *testing.T) []packInfo {
	t.Helper()
	var out []packInfo
	for _, cat := range categories {
		entries, err := os.ReadDir(cat)
		if err != nil {
			continue // a category with no packs is allowed
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			path := filepath.Join(cat, e.Name())
			out = append(out, packInfo{
				path: path,
				dir:  cat,
				rel:  path,
				stem: strings.TrimSuffix(e.Name(), ".yaml"),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}

// TestNoRuleIsDuplicatedUnderTwoIDs: two rule IDs matching the same thing is
// not a near-miss, it is the same detection counted twice. The assembler treats
// each detector as an independent sighting, so a duplicated rule doubles a
// component's occurrences and feeds the confidence calculus corroboration that
// does not exist — in a tool whose whole claim is that evidence is traceable.
//
// This is not hypothetical. embeddings/instructor.yaml and
// embeddings/instructor-embedding.yaml were the same pack under two names,
// left behind when the pack was renamed in the overlay repo but only added,
// never removed, in the embedded copy. One line of Python produced four
// occurrences of one component, two per rule.
func TestNoRuleIsDuplicatedUnderTwoIDs(t *testing.T) {
	rs, err := ruleengine.Load(FS(), nil, "", nil, os.ReadFile)
	if err != nil {
		t.Fatalf("embedded ruleset does not load: %v", err)
	}
	// Key on what decides whether a rule fires and what it claims. Two rules
	// agreeing on all of it are the same rule wearing two IDs; rules that
	// merely share a keyword differ in pattern or kind and are untouched
	// (TestSharedKeywordAcrossRules covers that case deliberately).
	type shape struct {
		kind, provider, pattern, langs, keywords, regions string
	}
	norm := func(ss []string) string {
		c := append([]string(nil), ss...)
		sort.Strings(c)
		return strings.Join(c, "\x00")
	}
	seen := map[shape]string{}
	for _, r := range rs.Rules {
		s := shape{
			kind:     r.Kind,
			provider: r.Provider,
			pattern:  r.Pattern,
			langs:    norm(r.Languages),
			keywords: norm(r.Keywords),
			regions:  norm(r.Regions),
		}
		if first, ok := seen[s]; ok {
			t.Errorf("rules %q and %q are the same rule under two IDs: identical kind, provider, pattern, languages, keywords and regions.\n"+
				"Every match will produce two occurrences of one component and inflate its confidence.", first, r.ID)
			continue
		}
		seen[s] = r.ID
	}
}
