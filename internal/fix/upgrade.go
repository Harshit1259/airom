package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// UpgradeStatus is how far one click's upgrade got.
type UpgradeStatus string

const (
	// UpgradeDone: the new version is in place — pinned where it is pinned,
	// installed by the package manager, and read back from the environment.
	UpgradeDone UpgradeStatus = "upgraded"
	// UpgradePinned: the manifest now pins the new version, but no package
	// manager ran (none wired, none on PATH, or no virtualenv to install into).
	// The reason says which, so the last step is obvious.
	UpgradePinned UpgradeStatus = "pinned"
	// UpgradeFailed: nothing usable changed, or the change was rolled back.
	UpgradeFailed UpgradeStatus = "failed"
)

// UpgradeOptions configures Upgrade.
type UpgradeOptions struct {
	// Install runs the package manager after the pins move. Without it Upgrade
	// stops at the manifest edit, which is the old --fix behavior.
	Install bool
	// Verify runs the resolver dry-run before and after the edit, and rolls
	// the edit back when the fix is what broke resolution.
	Verify bool
	// Out receives the package manager's output as it runs.
	Out io.Writer
	// HTTP is used for the closing OSV check; nil means a default client.
	HTTP Doer
}

// UpgradeResult is everything one upgrade did, for the row and the summary.
type UpgradeResult struct {
	Package string
	From    string
	To      string
	Status  UpgradeStatus
	Reason  string // why it stopped short, or how it failed

	Pins    []Result        // manifest lines rewritten
	Install []InstallResult // what each package manager run did
	Detail  []string        // the tail of the failing tool's output

	// Installed is the version read back from the environment afterwards
	// ("" when it cannot be read). Advisories is OSV's count for it, -1 when
	// the check did not run.
	Installed  string
	Advisories int
}

// Upgrade moves one package from its vulnerable version to t.Fixed for real.
//
// A pinned package goes through the proved manifest edit (Apply) and then the
// project's own package manager, so the lockfile and the installed copy follow
// the pin. A package with no pin to rewrite — a version range resolved by a
// lockfile, or a copy found installed in a virtualenv — is upgraded by asking
// its package manager for that exact version, which updates the manifest and
// the lockfile itself.
//
// Afterwards the installed version is read back from the environment and
// checked against OSV, so "upgraded" means the new version is what is there,
// not that a command exited zero.
func Upgrade(ctx context.Context, root string, t Target, opts UpgradeOptions) UpgradeResult {
	res := UpgradeResult{Package: t.Package, From: t.Current, To: t.Fixed, Advisories: -1}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}

	switch {
	case t.Fixable:
		upgradePinned(ctx, root, t, opts, out, &res)
	case len(t.Direct) > 0 && opts.Install:
		upgradeDirect(ctx, root, t, out, &res)
	default:
		res.Status = UpgradeFailed
		res.Reason = t.Reason
		if res.Reason == "" {
			res.Reason = "no manifest pin to rewrite"
		}
		return res
	}
	if res.Status == UpgradeFailed {
		return res
	}

	res.Installed = installedVersion(ctx, root, t, res.Pins)
	check := res.Installed
	if check == "" {
		check = t.Fixed
	}
	if n, err := CheckVersion(ctx, opts.HTTP, t.Ecosystem, t.Package, check); err == nil {
		res.Advisories = n
	}
	if res.Status == UpgradeDone && res.Installed != "" && !sameVersion(res.Installed, t.Fixed) {
		// The package manager ran and something else is in place. Saying
		// "upgraded" here would be the over-claim this check exists to catch.
		res.Status = UpgradeFailed
		res.Reason = fmt.Sprintf("the package manager finished, but %s %s is installed, not %s",
			t.Package, res.Installed, t.Fixed)
	}
	return res
}

func upgradePinned(ctx context.Context, root string, t Target, opts UpgradeOptions, out io.Writer, res *UpgradeResult) {
	var baseline []VerifyResult
	if opts.Verify {
		baseline = Verify(ctx, root, Manifests([]Target{t}))
	}

	pins, err := Apply(root, t)
	res.Pins = pins
	if len(pins) == 0 {
		res.Status, res.Reason = UpgradeFailed, errString(err)
		return
	}
	if err != nil {
		// Some manifests moved, some refused: the package is still pinned
		// vulnerable somewhere, so this is not done whatever happens next.
		res.Status = UpgradeFailed
		res.Reason = fmt.Sprintf("only %d of %d manifest(s) updated: %s", len(pins), len(t.Sites), err)
		return
	}

	manifests := make([]string, 0, len(pins))
	for _, p := range pins {
		manifests = append(manifests, p.File)
	}

	if opts.Verify {
		after := Verify(ctx, root, manifests)
		if attr := Attribute(baseline, after); Introduced(attr) {
			for _, p := range pins {
				_ = Revert(root, p)
			}
			res.Pins = nil
			res.Status = UpgradeFailed
			res.Reason = fmt.Sprintf("%s %s does not resolve with the rest of the project; the pin was put back", t.Package, t.Fixed)
			for _, v := range after {
				if v.Status == VerifyConflict {
					res.Detail = v.Detail
					break
				}
			}
			return
		}
	}

	if !opts.Install {
		res.Status, res.Reason = UpgradePinned, "pin rewritten; the package manager was not run"
		return
	}
	res.Install = Install(ctx, root, manifests, out)
	res.Status = UpgradeDone
	for _, ir := range res.Install {
		switch ir.Status {
		case InstallFailed:
			// The pin is put back. A manifest naming a version the lockfile
			// and the installed tree do not have is a broken project, and
			// leaving it that way after a failed upgrade is worse than not
			// having tried.
			restored := true
			for _, p := range pins {
				if Revert(root, p) != nil {
					restored = false
				}
			}
			res.Status, res.Detail = UpgradeFailed, ir.Detail
			if restored {
				res.Pins = nil
				res.Reason = fmt.Sprintf("%s could not install %s %s, so the pin was put back", ir.Tool, t.Package, t.Fixed)
			} else {
				res.Reason = fmt.Sprintf("%s could not install %s %s, and the pin could not be put back — check %s", ir.Tool, t.Package, t.Fixed, ir.Manifest)
			}
			return
		case InstallSkipped:
			res.Status = UpgradePinned
			res.Reason = "pin rewritten; not installed: " + ir.Reason
		case InstallDirty:
			if res.Status == UpgradeDone {
				res.Reason = ir.Reason
			}
		}
	}
}

// upgradeDirect asks the package manager for the exact version, for a package
// that has no pin line AIROM can rewrite.
func upgradeDirect(ctx context.Context, root string, t Target, out io.Writer, res *UpgradeResult) {
	ran := false
	for _, d := range t.Direct {
		argv, dir, why := directCommand(root, t, d)
		if why != "" {
			res.Status, res.Reason = UpgradeFailed, why
			return
		}
		if _, err := exec.LookPath(argv[0]); err != nil && !filepath.IsAbs(argv[0]) {
			res.Status, res.Reason = UpgradeFailed, argv[0]+" is not on PATH"
			return
		}
		rel := "."
		if base, err := filepath.Abs(root); err == nil {
			if r, err := filepath.Rel(base, dir); err == nil {
				rel = r
			}
		}
		fmt.Fprintf(out, "  $ %s   (in %s)\n", strings.Join(argv, " "), filepath.ToSlash(rel))
		tail, halted, err := runStreaming(ctx, dir, argv, InstallTimeout, out, "    ")
		ir := InstallResult{Manifest: filepath.ToSlash(rel), Tool: path.Base(argv[0]), Status: InstallOK}
		if err != nil {
			ir.Status, ir.Detail = InstallFailed, tail
			ir.Reason = strings.Join(argv, " ") + " failed"
			if halted {
				ir.Reason = haltReason(ir.Tool, err)
			}
			res.Install = append(res.Install, ir)
			res.Status, res.Reason, res.Detail = UpgradeFailed, ir.Reason, tail
			return
		}
		res.Install = append(res.Install, ir)
		ran = true
	}
	if ran {
		res.Status = UpgradeDone
	}
}

// directCommand builds the package-manager command for one direct site.
func directCommand(root string, t Target, d Site) (argv []string, dir, why string) {
	abs, err := resolveInRoot(root, d.File)
	if err != nil {
		return nil, "", err.Error()
	}
	spec := t.Package + "@" + t.Fixed
	switch t.Ecosystem {
	case "npm":
		dir = filepath.Dir(abs)
		if !declaresDependency(filepath.Join(dir, "package.json"), t.Package) {
			return nil, "", t.Package + " is a transitive dependency here; upgrade the package that depends on it"
		}
		switch {
		case lockPresent("pnpm-lock.yaml")(dir):
			return []string{"pnpm", "add", spec}, dir, ""
		case lockPresent("yarn.lock")(dir):
			return []string{"yarn", "add", spec}, dir, ""
		default:
			return []string{"npm", "install", "--no-audit", "--no-fund", spec}, dir, ""
		}
	case "pypi":
		py, venv := venvPython(abs)
		if py == "" {
			return nil, "", "no virtualenv owns " + d.File + "; activate it and re-run"
		}
		return []string{py, "-m", "pip", "install", "--no-input", t.Package + "==" + t.Fixed}, venv, ""
	}
	return nil, "", "no package manager wired to upgrade " + t.Ecosystem + " packages directly"
}

// venvPython finds the interpreter of the virtualenv a site-packages path lives
// in: <venv>/lib/pythonX.Y/site-packages/... -> <venv>/bin/python.
func venvPython(abs string) (python, venv string) {
	p := filepath.ToSlash(abs)
	i := strings.Index(p, "/lib/python")
	if i < 0 {
		return "", ""
	}
	venv = filepath.FromSlash(p[:i])
	for _, name := range []string{"python", "python3"} {
		if c := filepath.Join(venv, "bin", name); isExecutable(c) {
			return c, venv
		}
	}
	return "", ""
}

// declaresDependency reports whether package.json lists name in any of its
// dependency maps. `npm install name@x` on a package that is only transitive
// would make it a new top-level dependency, which is not what anyone asked for.
func declaresDependency(pkgJSON, name string) bool {
	data, err := os.ReadFile(pkgJSON) // #nosec G304 -- confined to the scan root by the caller
	if err != nil {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil {
		return false
	}
	for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		var deps map[string]string
		if json.Unmarshal(doc[k], &deps) == nil {
			if _, ok := deps[name]; ok {
				return true
			}
		}
	}
	return false
}

// installedVersion reads back what the environment now holds, so "upgraded"
// is a fact about the environment rather than about an exit code. Returns ""
// when this ecosystem has nothing to read.
func installedVersion(ctx context.Context, root string, t Target, pins []Result) string {
	var dirs []string
	for _, p := range pins {
		if abs, err := resolveInRoot(root, p.File); err == nil {
			dirs = append(dirs, filepath.Dir(abs))
		}
	}
	for _, d := range t.Direct {
		if abs, err := resolveInRoot(root, d.File); err == nil {
			dirs = append(dirs, filepath.Dir(abs))
		}
	}
	for _, dir := range dirs {
		switch t.Ecosystem {
		case "npm":
			var pj struct {
				Version string `json:"version"`
			}
			data, err := os.ReadFile(filepath.Join(dir, "node_modules", filepath.FromSlash(t.Package), "package.json")) // #nosec G304 -- under the scan root
			if err == nil && json.Unmarshal(data, &pj) == nil && pj.Version != "" {
				return pj.Version
			}
		case "pypi":
			py := pythonFor(dir)
			if p, _ := venvPython(dir); p != "" {
				py = p
			}
			if py == "python3" && os.Getenv("VIRTUAL_ENV") == "" {
				continue // never report the system interpreter as this project's environment
			}
			out, _, err := run(ctx, dir, []string{py, "-m", "pip", "show", t.Package}, probeTimeout)
			if err != nil {
				continue
			}
			for _, l := range strings.Split(out, "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Version:"); ok {
					return strings.TrimSpace(v)
				}
			}
		case "golang":
			out, _, err := run(ctx, dir, []string{"go", "list", "-m", "-f", "{{.Version}}", t.Package}, probeTimeout)
			if err == nil {
				return strings.TrimSpace(out)
			}
		}
	}
	return ""
}

// sameVersion compares two version strings the way the ecosystems print them:
// a leading "v" (Go) is not a difference.
func sameVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

func errString(err error) string {
	if err == nil {
		return "nothing was changed"
	}
	return err.Error()
}

// Headline picks the line of a failed tool's output that says what went wrong:
// the first one carrying an error code or an ERROR marker, else the last line.
// npm ends a failure with advice ("retry with --force") and pip with a hint;
// neither is the reason.
func Headline(detail []string) string {
	for i, l := range detail {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "npm error"))
		if strings.HasPrefix(strings.ToLower(t), "could not resolve dependency") && i+1 < len(detail) {
			next := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(detail[i+1]), "npm error"))
			return "npm could not resolve dependency: " + next
		}
	}
	for _, l := range detail {
		t := strings.TrimSpace(l)
		low := strings.ToLower(t)
		if strings.Contains(t, "ERESOLVE") || strings.HasPrefix(low, "error:") ||
			strings.Contains(low, "no matching distribution") || strings.Contains(low, "could not find a version") {
			t = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "npm error"), "npm ERR!"))
			if t != "" && !strings.HasPrefix(t, "code ") {
				return t
			}
		}
	}
	if len(detail) == 0 {
		return ""
	}
	return strings.TrimSpace(detail[len(detail)-1])
}
