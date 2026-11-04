package socialgo

import (
	"fmt"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// ClassifiedSocialVuln is a heuristic finding derived from a social
// engineering module response. Only Stage=hit + OK produces a real
// vuln — that's a live capture (credential, session, click). Result
// stage is info; miss/error/done are skip.
type ClassifiedSocialVuln struct {
	Name     string
	Severity string
	Evidence string
}

// ClassifySocial turns a social module response into a classified vuln
// list. Keyed on Stage + OK. Detail carries the payload-specific
// context (captured form values, session cookie, redirect target).
func ClassifySocial(d proto.SocialData) []ClassifiedSocialVuln {
	if d.Done || !d.OK {
		return nil
	}

	evidence := d.Detail
	if evidence == "" {
		evidence = d.Message
	}

	switch d.Stage {
	case "hit":
		return []ClassifiedSocialVuln{{
			Name:     "Social engineering hit — credential or session captured",
			Severity: "high",
			Evidence: evidence,
		}}
	case "result":
		return []ClassifiedSocialVuln{{
			Name:     fmt.Sprintf("Social engineering result observed: %s", d.Message),
			Severity: "info",
			Evidence: evidence,
		}}
	default:
		return nil
	}
}
