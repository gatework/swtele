package cli

import (
	"regexp"
	"strings"
)

// usageErrors translates cobra's and pflag's usage errors, which are
// English and not configurable.
var usageErrors = []struct {
	re   *regexp.Regexp
	text string
}{
	{regexp.MustCompile(`^unknown command "([^"]*)" for "[^"]*"`), `未知子命令 "$1"`},
	{regexp.MustCompile(`^unknown flag: (\S+)`), `未知参数 $1`},
	{regexp.MustCompile(`^unknown shorthand flag: '\S' in (\S+)`), `未知参数 $1`},
	{regexp.MustCompile(`^flag needs an argument: (.+)`), `参数缺少取值：$1`},
	{regexp.MustCompile(`^invalid argument "([^"]*)" for "([^"]*)" flag: .*`), `参数 $2 的取值 "$1" 无效`},
	{regexp.MustCompile(`^accepts (\d+) arg\(s\), received (\d+)`), `需要 $1 个位置参数，实际 $2 个`},
	{regexp.MustCompile(`^required flag\(s\) (.+) not set`), `缺少必需参数 $1`},
}

// errText renders an error for the terminal: usage errors in Chinese with
// a hint, everything else with the error prefix.
func errText(err error) string {
	msg := err.Error()
	for _, u := range usageErrors {
		if u.re.MatchString(msg) {
			first, _, _ := strings.Cut(msg, "\n")
			return errPrefix + u.re.ReplaceAllString(first, u.text) + errUsageHint
		}
	}
	return errPrefix + msg
}
