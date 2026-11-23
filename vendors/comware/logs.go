package comware

import (
	"regexp"
	"strings"
	"time"

	"github.com/gatework/swtele"
	"github.com/gatework/swtele/vendors/internal/clidoc"
)

var (
	logHeader = regexp.MustCompile(`^\s*(?:Log buffer:|Max buffer size|Actual buffer size|Dropped messages|Overwritten messages|Current messages|Channel number|Channel name)`)
	// logEntry: "%Nov 23 17:38:09:248 2026 HOST MOD/4/MNEMONIC: text".
	logEntry = regexp.MustCompile(`^%(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}:\d{3} \d{4}) \S+ ([A-Za-z0-9_]+)/(\d)/([A-Za-z0-9_]+(?: [A-Za-z0-9_]+)?):\s?(.*)$`)
	// logPort finds the interface a message names.
	logPort = regexp.MustCompile(`(?:Interface |interface |port )?\b((?:Ten-|Forty|Hundred|M-)?Giga\w*\d[\d/]*|Bridge-Aggregation\d+|Route-Aggregation\d+|FortyGigE\d[\d/]*|Smartrate-Ethernet\d[\d/]*|Vlan-interface\d+)\b`)
)

// noise are the mnemonics of the collector's own sessions.
var noise = map[string]bool{"SHELL_CMD": true, "SHELL_LOGIN": true, "SHELL_LOGOUT": true, "SHELL_CMD_MATCHFAIL": true, "SSHS_CONNECT": true, "SSHS_LOG": true, "SSHS_DISCONNECT": true, "SHELL_CMD_CONFIRM": true}

func decodeLog(doc *clidoc.Doc, st *state) {
	var last *swtele.LogEvent
	for _, l := range doc.Lines {
		text := l.Text
		switch {
		case logHeader.MatchString(text):
		case logEntry.MatchString(text):
			m := logEntry.FindStringSubmatch(text)
			last = nil
			if noise[m[4]] {
				break
			}
			e := swtele.LogEvent{Module: m[2], Severity: clidoc.Int(m[3]).Or(0), Mnemonic: m[4], Text: m[5]}
			if t, err := time.ParseInLocation("Jan _2 15:04:05.000 2006", fixMillis(m[1]), st.loc); err == nil {
				e.At = swtele.Some(t.UTC())
			}
			if p := logPort.FindStringSubmatch(m[5]); p != nil {
				e.Interface = p[1]
			}
			st.dev.Logs = append(st.dev.Logs, e)
			last = &st.dev.Logs[len(st.dev.Logs)-1]
		case !strings.HasPrefix(text, "%") && !blank(text):
			// A message continued on the next line.
			if last != nil {
				last.Text += " " + strings.TrimSpace(text)
			}
		default:
			continue
		}
		doc.Mark(l)
	}
}

// fixMillis turns "17:38:09:248" into "17:38:09.248" for time.Parse.
func fixMillis(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.LastIndex(s, ":"); i > 0 && len(s) > i+4 && s[i+4] == ' ' {
		return s[:i] + "." + s[i+1:]
	}
	return s
}
