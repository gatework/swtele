package check

import "github.com/gatework/netops/assess"

// weights are the points a finding of each severity costs.
var weights = map[assess.Severity]int{
	assess.SeverityCritical: 25, assess.SeverityHigh: 10, assess.SeverityMedium: 4, assess.SeverityLow: 1,
}

// Score grades a device assessment from 100 (no finding) down to 0.
// Rules skipped for missing evidence cost nothing: the score says what
// was observed, and the coverage says what was not.
func Score(a assess.Assessment) int {
	score := 100
	for _, f := range a.Findings {
		score -= weights[f.Severity]
	}
	return max(score, 0)
}
