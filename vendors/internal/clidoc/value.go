package clidoc

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/swtele"
)

// nulls are the cell spellings for "not reported".
var nulls = map[string]bool{"": true, "-": true, "--": true, "---": true, "n/a": true, "na": true, "overflow": true, "unknown": true}

// Null reports a cell that means "not reported".
func Null(s string) bool { return nulls[strings.ToLower(strings.TrimSpace(s))] }

// Uint parses a non-negative count; null spellings are absent.
func Uint(s string) swtele.Opt[uint64] {
	s = strings.TrimSpace(s)
	if Null(s) {
		return swtele.Opt[uint64]{}
	}
	v, err := strconv.ParseUint(strings.ReplaceAll(s, ",", ""), 10, 64)
	if err != nil {
		return swtele.Opt[uint64]{}
	}
	return swtele.Some(v)
}

// Int parses an integer; null spellings are absent.
func Int(s string) swtele.Opt[int] {
	s = strings.TrimSpace(s)
	if Null(s) {
		return swtele.Opt[int]{}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return swtele.Opt[int]{}
	}
	return swtele.Some(v)
}

// Float parses a decimal, tolerating a trailing unit or percent sign
// ("35", "62.8%", "-2.31", "28.12 C", "126 W").
func Float(s string) swtele.Opt[float64] {
	s = strings.TrimSpace(s)
	if Null(s) {
		return swtele.Opt[float64]{}
	}
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.' || s[end] == '-' || s[end] == '+') {
		end++
	}
	v, err := strconv.ParseFloat(s[:end], 64)
	if err != nil {
		return swtele.Opt[float64]{}
	}
	return swtele.Some(v)
}

var speedPattern = regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*([kmgt])(?:b(?:ps|/s)?|bit/s)?`)

// Speed parses "1G(a)", "2.5G", "100M", "10Gbps", "25 Gb/s", "1000" (Mb/s)
// into bit/s; "auto" and nulls are absent.
func Speed(s string) swtele.Opt[uint64] {
	s = strings.TrimSpace(s)
	if m := speedPattern.FindStringSubmatch(s); m != nil {
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return swtele.Opt[uint64]{}
		}
		mult := map[string]float64{"k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}[strings.ToLower(m[2])]
		return swtele.Some(uint64(v * mult))
	}
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return swtele.Some(v * 1_000_000)
	}
	return swtele.Opt[uint64]{}
}

var unitWords = []struct {
	re   *regexp.Regexp
	unit time.Duration
}{
	{regexp.MustCompile(`(\d+)\s*(?:years?|y)(?:[^a-z(]|$)`), 365 * 24 * time.Hour},
	{regexp.MustCompile(`(\d+)\s*(?:weeks?|week\(s\)|w)(?:[^a-z(]|$)`), 7 * 24 * time.Hour},
	{regexp.MustCompile(`(\d+)\s*(?:days?|day\(s\)|d)(?:[^a-z(]|$)`), 24 * time.Hour},
	{regexp.MustCompile(`(\d+)\s*(?:hours?|hour\(s\)|h)(?:[^a-z(]|$)`), time.Hour},
	{regexp.MustCompile(`(\d+)\s*(?:minutes?|minute\(s\)|mins?|m)(?:[^a-z(]|$)`), time.Minute},
	{regexp.MustCompile(`(\d+)\s*(?:seconds?|second\(s\)|secs?|s)(?:[^a-z(]|$)`), time.Second},
}

var (
	clockPattern = regexp.MustCompile(`^(?:(\d+)d)?(\d+):(\d{2}):(\d{2})$`)
	compactUnits = regexp.MustCompile(`^(?:\d+[ywdhms])+$`)
	compactPart  = regexp.MustCompile(`(\d+)([ywdhms])`)
)

// Duration parses the relative durations CLIs print: "161 weeks 5 days 7
// hours 26 minutes", "426 days, 20 hours, 10 minutes, 25 seconds",
// "13week(s) 1day(s)", "3y34w", "2d03h", "01:02:03", "1d02:03:04" and
// "0568h44m". Unparsable text and nulls are absent.
func Duration(s string) swtele.Opt[time.Duration] {
	s = strings.ToLower(strings.TrimSpace(s))
	if Null(s) {
		return swtele.Opt[time.Duration]{}
	}
	if m := clockPattern.FindStringSubmatch(s); m != nil {
		d := atoi(m[1])*24*3600 + atoi(m[2])*3600 + atoi(m[3])*60 + atoi(m[4])
		return swtele.Some(time.Duration(d) * time.Second)
	}
	if compactUnits.MatchString(s) {
		var total time.Duration
		for _, m := range compactPart.FindAllStringSubmatch(s, -1) {
			total += time.Duration(atoi(m[1])) * compactUnit(m[2])
		}
		return swtele.Some(total)
	}
	var total time.Duration
	found := false
	for _, u := range unitWords {
		for _, m := range u.re.FindAllStringSubmatch(s, -1) {
			total += time.Duration(atoi(m[1])) * u.unit
			found = true
		}
	}
	if !found {
		return swtele.Opt[time.Duration]{}
	}
	return swtele.Some(total)
}

func compactUnit(u string) time.Duration {
	switch u {
	case "y":
		return 365 * 24 * time.Hour
	case "w":
		return 7 * 24 * time.Hour
	case "d":
		return 24 * time.Hour
	case "h":
		return time.Hour
	case "m":
		return time.Minute
	}
	return time.Second
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

var zonePattern = regexp.MustCompile(`([+-])(\d{1,2}):(\d{2})(?::(\d{2}))?$`)

// Timestamp parses "2023-10-18 10:46:00" followed by an optional zone
// name and offset ("beijing+08:00:00", "BJ+8+08:00:00"). Without an offset
// the device-local time is assumed to be in loc.
func Timestamp(s string, loc *time.Location) swtele.Opt[time.Time] {
	s = strings.TrimSpace(s)
	if len(s) < 19 {
		return swtele.Opt[time.Time]{}
	}
	base, zone := s[:19], strings.TrimSpace(s[19:])
	if m := zonePattern.FindStringSubmatch(zone); m != nil {
		off := atoi(m[2])*3600 + atoi(m[3])*60
		if m[1] == "-" {
			off = -off
		}
		loc = time.FixedZone("device", off)
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", base, loc)
	if err != nil {
		return swtele.Opt[time.Time]{}
	}
	return swtele.Some(t.UTC())
}
