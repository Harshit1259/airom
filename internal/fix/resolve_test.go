package fix

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

// fakeInternet serves a PyPI JSON API, an npm registry, and OSV's batch
// endpoint from one local server, and points the package at it for the test.
// vulns maps "name@version" to how many advisories OSV should report.
func fakeInternet(t *testing.T, pypi map[string]map[string]bool, npm map[string][]string, vulns map[string]int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/pypi/"):
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/pypi/"), "/json")
			rels, ok := pypi[name]
			if !ok {
				http.NotFound(w, r)
				return
			}
			doc := map[string]any{}
			for v, yanked := range rels {
				doc[v] = []map[string]bool{{"yanked": yanked}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"releases": doc})
		case strings.HasPrefix(r.URL.Path, "/npm/"):
			name := strings.TrimPrefix(r.URL.Path, "/npm/")
			vs := map[string]any{}
			for _, v := range npm[name] {
				vs[v] = map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": vs})
		case r.URL.Path == "/osv":
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Queries []struct {
					Package struct{ Name string } `json:"package"`
					Version string                `json:"version"`
				} `json:"queries"`
			}
			_ = json.Unmarshal(body, &req)
			type res struct {
				Vulns []map[string]string `json:"vulns,omitempty"`
			}
			out := make([]res, len(req.Queries))
			for i, q := range req.Queries {
				for n := 0; n < vulns[q.Package.Name+"@"+q.Version]; n++ {
					out[i].Vulns = append(out[i].Vulns, map[string]string{"id": "GHSA-x"})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	oldOSV, oldPyPI, oldNPM := OSVBatchEndpoint, PyPIBase, NPMBase
	OSVBatchEndpoint, PyPIBase, NPMBase = srv.URL+"/osv", srv.URL+"/pypi", srv.URL+"/npm"
	t.Cleanup(func() { OSVBatchEndpoint, PyPIBase, NPMBase = oldOSV, oldPyPI, oldNPM })
}

// TestResolvePicksTheFirstCleanRelease: the advisory's fixed version is only
// where THAT advisory stops. When OSV lists something newer against it, the
// target moves up to the first published release with no advisory at all —
// skipping pre-releases and yanked uploads on the way.
func TestResolvePicksTheFirstCleanRelease(t *testing.T) {
	fakeInternet(t,
		map[string]map[string]bool{"langchain": {
			"0.0.310": false, "0.1.0": false, "0.1.1rc1": false, "0.1.1": true, "0.1.2": false, "0.2.0": false,
		}},
		nil,
		map[string]int{"langchain@0.1.0": 2, "langchain@0.1.1rc1": 0, "langchain@0.1.1": 0},
	)
	got := Resolve(t.Context(), []Target{{Package: "langchain", Ecosystem: "pypi", Current: "0.0.310", Fixed: "0.1.0"}}, ResolveOptions{})[0]

	if got.Fixed != "0.1.2" {
		t.Errorf("Fixed = %q, want 0.1.2 (0.1.0 still vulnerable, 0.1.1rc1 pre-release, 0.1.1 yanked)", got.Fixed)
	}
	if got.Online != OnlineClean || got.Advisory != "0.1.0" || got.Latest != "0.2.0" {
		t.Errorf("Online=%q Advisory=%q Latest=%q", got.Online, got.Advisory, got.Latest)
	}
	if !strings.Contains(got.Note, "advisory says 0.1.0") {
		t.Errorf("Note = %q, want it to explain why the target moved", got.Note)
	}
	if !got.Major {
		t.Error("0.0.310 → 0.1.2 leaves the 0.0 line; Major must be recomputed for the new target")
	}
}

// TestResolveKeepsTheAdvisoryVersionWhenItIsClean: no movement when the
// advisory's own version is already clean.
func TestResolveKeepsTheAdvisoryVersionWhenItIsClean(t *testing.T) {
	fakeInternet(t, nil, map[string][]string{"openai": {"4.0.0", "4.20.0", "4.21.0"}}, nil)
	got := Resolve(t.Context(), []Target{{Package: "openai", Ecosystem: "npm", Current: "4.0.0", Fixed: "4.20.0"}}, ResolveOptions{})[0]
	if got.Fixed != "4.20.0" || got.Online != OnlineClean || got.Note != "" {
		t.Errorf("got Fixed=%q Online=%q Note=%q", got.Fixed, got.Online, got.Note)
	}
}

// TestResolveSaysWhenNothingIsClean: every release in reach still has
// advisories. The target is the lowest one that clears what the scan found,
// and the row says so instead of implying it is clean.
func TestResolveSaysWhenNothingIsClean(t *testing.T) {
	fakeInternet(t,
		map[string]map[string]bool{"torch": {"1.0.0": false, "2.0.0": false, "2.1.0": false}},
		nil,
		map[string]int{"torch@2.0.0": 3, "torch@2.1.0": 1},
	)
	got := Resolve(t.Context(), []Target{{Package: "torch", Ecosystem: "pypi", Current: "1.0.0", Fixed: "2.0.0"}}, ResolveOptions{})[0]
	if got.Fixed != "2.0.0" || got.Online != OnlineStillVulnerable {
		t.Errorf("got Fixed=%q Online=%q", got.Fixed, got.Online)
	}
	if !strings.Contains(got.Note, "OSV still lists 3") {
		t.Errorf("Note = %q", got.Note)
	}
}

// TestResolveDegradesPerPackage: a registry that does not know the package
// fails that row alone, keeping the advisory version.
func TestResolveDegradesPerPackage(t *testing.T) {
	fakeInternet(t, map[string]map[string]bool{}, nil, nil)
	got := Resolve(t.Context(), []Target{{Package: "ghost", Ecosystem: "pypi", Current: "1.0", Fixed: "1.1"}}, ResolveOptions{})[0]
	if got.Fixed != "1.1" || got.Online != OnlineFailed || !strings.Contains(got.Note, "not found") {
		t.Errorf("got Fixed=%q Online=%q Note=%q", got.Fixed, got.Online, got.Note)
	}
}

func TestIsStable(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.3": true, "v1.2.3": true, "0.0.310": true, "1.2.3.post1": true, "v2.0.0+incompatible": true,
		"1.2.3rc1": false, "1.2.3-beta.1": false, "2.0.0a1": false, "1.0.dev3": false,
		"v0.0.0-20240101000000-abcdef123456": false, "": false, "1.": false,
	} {
		if got := isStable(v); got != want {
			t.Errorf("isStable(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestRegistryEscapes(t *testing.T) {
	if got := npmEscape("@langchain/core"); got != "@langchain%2Fcore" {
		t.Errorf("npmEscape = %q", got)
	}
	if got := goEscape("github.com/Azure/azure-sdk"); got != "github.com/!azure/azure-sdk" {
		t.Errorf("goEscape = %q", got)
	}
}

func TestHeadline(t *testing.T) {
	npm := []string{
		"npm error code ERESOLVE",
		"npm error ERESOLVE unable to resolve dependency tree",
		"npm error Could not resolve dependency:",
		`npm error peer @langchain/core@">=0.3.58 <0.4.0" from langchain@0.3.37`,
		"npm error this command with --force or --legacy-peer-deps",
	}
	if got := Headline(npm); !strings.Contains(got, `peer @langchain/core@">=0.3.58 <0.4.0"`) {
		t.Errorf("Headline(npm) = %q, want the dependency that could not resolve", got)
	}
	pip := []string{"Collecting x", "ERROR: No matching distribution found for x==9.9", "[notice] upgrade pip"}
	if got := Headline(pip); !strings.Contains(got, "No matching distribution") {
		t.Errorf("Headline(pip) = %q", got)
	}
}

// TestDirectSitesOnlyForDeclaredDependencies: a range in package.json can be
// upgraded by npm in place; a package seen only in the lockfile is transitive,
// and `npm install` on it would add a new top-level dependency.
func TestDirectSitesOnlyForDeclaredDependencies(t *testing.T) {
	ranged := comp("openai", "4.2.1", "pkg:npm/openai@4.2.1", "manifest/npm", "package.json", 3, `"openai": "^4.0.0"`,
		vuln("CVE-1", airom.VulnHigh, "4.3.0"))
	transitive := comp("core", "0.1.0", "pkg:npm/core@0.1.0", "manifest/npm-lock", "package-lock.json", 9, "",
		vuln("CVE-2", airom.VulnHigh, "0.2.0"))
	venv := comp("torch", "1.0.0", "pkg:pypi/torch@1.0.0", "manifest/pypi-installed",
		".venv/lib/python3.12/site-packages/torch-1.0.0.dist-info/METADATA", 1, "", vuln("CVE-3", airom.VulnHigh, "2.0.0"))

	ts := Plan(inventory(ranged, transitive, venv), false)
	by := map[string]Target{}
	for _, tg := range ts {
		by[tg.Package] = tg
	}
	if tg := by["openai"]; tg.Fixable || len(tg.Direct) != 1 || !tg.Upgradable() {
		t.Errorf("openai: Fixable=%v Direct=%v", tg.Fixable, tg.Direct)
	}
	if tg := by["core"]; tg.Upgradable() {
		t.Errorf("core (lockfile only) must not be upgradable directly: %+v", tg.Direct)
	}
	if tg := by["torch"]; len(tg.Direct) != 1 {
		t.Errorf("torch in a venv should be upgradable by that venv's pip: %+v", tg.Direct)
	}
}

// TestUpgradePinOnly: without Install the pin moves, the status says the
// package manager was not run, and the closing OSV check still runs.
func TestUpgradePinOnly(t *testing.T) {
	fakeInternet(t, nil, nil, nil)
	root := t.TempDir()
	write(t, root, "requirements.txt", "langchain==0.0.310\n")
	tg := target("langchain", "0.0.310", "1.3.9", "requirements.txt", 1, "langchain==0.0.310")
	tg.Ecosystem = "pypi"

	res := Upgrade(t.Context(), root, tg, UpgradeOptions{})
	if res.Status != UpgradePinned || len(res.Pins) != 1 || res.Advisories != 0 {
		t.Fatalf("got %+v", res)
	}
	data, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if string(data) != "langchain==1.3.9\n" {
		t.Errorf("requirements.txt = %q", data)
	}
}

// TestFailedInstallPutsThePinBack: a manifest naming a version its lockfile
// and node_modules do not have is a broken project. When the package manager
// refuses the new version, the pin goes back to what it was.
func TestFailedInstallPutsThePinBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stub package manager is a shell script")
	}
	fakeInternet(t, nil, nil, nil)
	bin := t.TempDir()
	write(t, bin, "npm", "#!/bin/sh\n[ \"$1\" = --version ] && { echo 10.0.0; exit 0; }\necho 'npm error code ERESOLVE'\necho 'npm error Could not resolve dependency:'\necho 'npm error peer x@1 from y@2'\nexit 1\n")
	if err := os.Chmod(filepath.Join(bin, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	root := t.TempDir()
	orig := `{"dependencies":{"langchain":"0.0.200"}}`
	write(t, root, "package.json", orig)
	tg := target("langchain", "0.0.200", "0.3.37", "package.json", 1, orig)
	tg.Ecosystem = "npm"

	res := Upgrade(t.Context(), root, tg, UpgradeOptions{Install: true})
	if res.Status != UpgradeFailed || !strings.Contains(res.Reason, "pin was put back") {
		t.Fatalf("got %+v", res)
	}
	if h := Headline(res.Detail); !strings.Contains(h, "peer x@1 from y@2") {
		t.Errorf("Headline = %q", h)
	}
	data, _ := os.ReadFile(filepath.Join(root, "package.json"))
	if string(data) != orig {
		t.Errorf("package.json = %q, want it restored", data)
	}
}
