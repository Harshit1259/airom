package airom

// Vulnerability is a known CVE affecting a component, matched by its purl
// against a vulnerability database (OSV.dev). Unlike an ArtifactRisk — which is
// AIROM's own statically-detected code-execution finding — a Vulnerability is a
// third-party advisory with a real id and CVSS score, so it projects into
// CycloneDX vulnerabilities[] with a genuine CVSSv3 rating (not method "other").
//
// The CVE overlay is opt-in (`--cve`): it queries a live database, so unlike the
// rest of AIROM it is neither offline nor deterministic across time (the same
// scan yields more CVEs as the database grows). It is scoped to the AI packages
// AIROM already inventories — it is not a general-purpose SCA scanner.
type Vulnerability struct {
	ID       string       `json:"id"`                     // CVE-YYYY-NNNN preferred; else the OSV/GHSA id
	Aliases  []string     `json:"aliases,omitempty"`      // the other ids for the same advisory
	Severity VulnSeverity `json:"severity"`               // from the CVSS base score, or "unknown"
	Score    float64      `json:"score,omitempty"`        // CVSS base score in [0,10], 0 when unknown
	Vector   string       `json:"vector,omitempty"`       // the CVSS vector string
	Summary  string       `json:"summary,omitempty"`      // one-line advisory summary
	Fixed    string       `json:"fixedVersion,omitempty"` // the first fixed version, when the advisory names one
	Source   string       `json:"source"`                 // "osv.dev"
	URL      string       `json:"url,omitempty"`          // advisory URL
	// KEV is set when this CVE appears in CISA's Known Exploited
	// Vulnerabilities catalog. Nil means the catalog had no entry for it — or
	// that no catalog was consulted at all; EnrichmentStats.CVE.KEVCatalog is
	// what tells those two apart, because "not listed" and "not checked" are
	// different claims and only one of them is reassuring.
	KEV *KEVRecord `json:"kev,omitempty"`
}

// KEVRecord is a CISA Known Exploited Vulnerabilities entry: the authoritative
// statement that a CVE has been exploited in the wild, as opposed to a CVSS
// score, which rates how bad exploitation WOULD be. The two are orthogonal — a
// medium-severity CVE under active exploitation outranks a critical nobody has
// ever used — so KEV never rewrites Severity or Score. It is reported alongside
// them and left for the reader, or for `--fail-on cve:kev`, to weigh.
type KEVRecord struct {
	// Added is the date CISA added the CVE to the catalog (YYYY-MM-DD).
	Added Date `json:"added"`
	// Due is the BOD 22-01 remediation deadline CISA set for federal civilian
	// agencies. It binds nobody else, and is carried because it is the closest
	// thing to an authoritative urgency signal attached to the entry.
	Due Date `json:"due,omitzero"`
	// Ransomware records CISA's "knownRansomwareCampaignUse: Known". The
	// catalog's other value is "Unknown", which is an absence of evidence
	// rather than evidence of absence, so only the positive is represented.
	Ransomware bool `json:"knownRansomwareUse,omitempty"`
	// Source identifies the catalog this record came from ("cisa-kev").
	Source string `json:"source"`
}

// VulnSeverity is the CVSS-derived severity bucket. Includes "critical" (which
// artifact risks do not) and "unknown" (an advisory with no parseable score).
type VulnSeverity string

// The CVSS v3.1 qualitative severity buckets, plus "unknown" for an advisory
// with no parseable score.
const (
	VulnCritical VulnSeverity = "critical"
	VulnHigh     VulnSeverity = "high"
	VulnMedium   VulnSeverity = "medium"
	VulnLow      VulnSeverity = "low"
	VulnUnknown  VulnSeverity = "unknown"
)

// VulnSeverities lists the buckets in descending order, for gate validation.
func VulnSeverities() []VulnSeverity {
	return []VulnSeverity{VulnCritical, VulnHigh, VulnMedium, VulnLow, VulnUnknown}
}

// SeverityFromScore buckets a CVSS base score (CVSS v3.1 qualitative bands).
func SeverityFromScore(score float64) VulnSeverity {
	switch {
	case score >= 9.0:
		return VulnCritical
	case score >= 7.0:
		return VulnHigh
	case score >= 4.0:
		return VulnMedium
	case score > 0.0:
		return VulnLow
	default:
		return VulnUnknown
	}
}
