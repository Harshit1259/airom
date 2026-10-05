package eol

import (
	"sort"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
)

// modelIDProp is where the assembler records the provider-native model id
// ("gpt-4-32k"), which is what a deprecation page names. Component.Name is the
// fallback: the two usually agree, but the raw id is authoritative.
const modelIDProp = "airom:model.id"

// Enrich attaches a Lifecycle to every model component the catalog knows about,
// mutating inv in place, and returns how many components it matched.
//
// It is deliberately narrow. Only hosted model references are matched: those
// are the components whose lifetime a provider controls unilaterally, where a
// retirement means the application stops working on a date. A local weights
// file on disk does not stop working because a vendor said so.
//
// Components with no catalog record are left untouched — no Lifecycle at all,
// which reads as "unknown". This function never writes a "supported" claim it
// cannot source.
func Enrich(inv *airom.Inventory, cat *Catalog, on airom.Date) int {
	if inv == nil || cat == nil {
		return 0
	}
	matched := 0
	for i := range inv.Components {
		c := &inv.Components[i]
		if !eligible(c.Kind) {
			continue
		}
		provider, ok := c.Provider.Value()
		if !ok || strings.TrimSpace(provider) == "" {
			continue // no provider → nothing to key on
		}
		var lc *airom.Lifecycle
		for _, id := range modelIDs(c) {
			if lc = cat.Lookup(provider, id, on); lc != nil {
				break
			}
		}
		if lc == nil {
			continue
		}
		c.EOL = lc
		matched++
	}
	if w := cat.StalenessWarning(on); w != "" {
		inv.Stats.Warnings = append(inv.Stats.Warnings, w)
		sort.Strings(inv.Stats.Warnings)
	}
	return matched
}

// eligible reports whether a component kind is provider-hosted, i.e. whether a
// vendor retirement announcement can break it.
func eligible(k airom.ComponentKind) bool {
	return k == airom.KindHostedLLM || k == airom.KindEmbeddingModel
}

// modelIDs returns the catalog keys this component could match, MOST SPECIFIC
// FIRST: the date-suffixed snapshot, then the model line it belongs to.
//
// Two of them are needed because identity and lifecycle are keyed differently.
// The assembler splits "gpt-5-2025-08-07" into name "gpt-5" plus version
// "2025-08-07", so that a pinned snapshot and the floating alias are ONE
// component (assemble.go, normalizeKey) — deliberate, and it stays. But a
// provider publishes retirement dates against the snapshot, and pinning one is
// exactly what gets a shutdown date, so keying the lookup on the line alone
// missed every snapshot record the catalog held: `model="gpt-5-2025-08-07"`
// reported no lifecycle claim at all while the catalog said shutdown
// 2026-12-11. Nine OpenAI records were unreachable that way.
//
// The snapshot is tried first because its dates are the specific truth; the
// line is the fallback, not an override. Only the dashed -YYYY-MM-DD form is
// reconstructed, because that is the only shape the assembler splits — an
// Anthropic id like claude-haiku-4-5-20251001 keeps its name intact and needs
// no reconstruction.
func modelIDs(c *airom.Component) []string {
	base := c.Name
	for _, p := range c.Props {
		if p.Name == modelIDProp && strings.TrimSpace(p.Value) != "" {
			base = p.Value
			break
		}
	}
	if v, ok := c.Version.Value(); ok && isDateVersion(v) {
		return []string{base + "-" + v, base}
	}
	return []string{base}
}

// isDateVersion reports whether v is exactly YYYY-MM-DD — the version string
// splitDateSuffix produces. Anything else is a real version and must not be
// glued onto a name to invent a model id that no provider published.
func isDateVersion(v string) bool {
	if len(v) != 10 || v[4] != '-' || v[7] != '-' {
		return false
	}
	for i := range 10 {
		if i == 4 || i == 7 {
			continue
		}
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}
