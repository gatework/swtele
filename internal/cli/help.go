package cli

import (
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

// usageTemplate is cobra's usage template with Chinese headings.
const usageTemplate = `用法：{{if .Runnable}}
  {{useLine .UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} <子命令>{{end}}{{if gt (len .Aliases) 0}}

别名：
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

示例：
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

子命令：{{range .Commands}}{{if .IsAvailableCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

参数：
{{cleanFlags .LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

全局参数：
{{cleanFlags .InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableSubCommands}}

运行 "{{.CommandPath}} <子命令> --help" 查看子命令用法。{{end}}
`

// templateFuncs guards the one-time registration of template functions:
// cobra keeps them in a global map.
var templateFuncs sync.Once

// localize installs the Chinese help on root and every subcommand: usage
// headings, the help command and the help/version flags. The shell
// completion command is disabled: its texts are not translatable.
func localize(root *cobra.Command) {
	templateFuncs.Do(func() {
		cobra.AddTemplateFunc("cleanFlags", cleanFlags)
		cobra.AddTemplateFunc("useLine", func(s string) string { return strings.ReplaceAll(s, "[flags]", "[参数]") })
	})
	root.SetUsageTemplate(usageTemplate)
	root.SetHelpCommand(&cobra.Command{
		Use: "help [子命令]", Short: shortHelp, Hidden: true,
		RunE: func(_ *cobra.Command, args []string) error {
			target, _, err := root.Find(args)
			if err != nil || target == nil {
				return root.Help()
			}
			return target.Help()
		},
	})
	root.CompletionOptions.DisableDefaultCmd = true
	root.Flags().BoolP("version", "v", false, flagVersion)
	root.SetVersionTemplate("swtele {{.Version}}\n")
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("help") == nil {
			c.Flags().BoolP("help", "h", false, flagHelp)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

var (
	// flagType matches pflag's value placeholder after a flag name.
	flagType = regexp.MustCompile(`^(\s*(?:-\w, )?--[\w-]+) (stringArray|strings|string|int|float64|float|duration)( +)`)
	// flagDefault matches pflag's default suffix.
	flagDefault = regexp.MustCompile(` \(default (.*)\)$`)
	typeNames   = map[string]string{
		"stringArray": "列表", "strings": "列表", "string": "文本", "int": "整数", "float": "小数", "float64": "小数", "duration": "时长",
	}
)

// cleanFlags translates pflag's usage lines: value placeholders and
// "(default X)" become Chinese, and "[=true|false]" on boolean flags is
// blanked. Placeholders are padded to their English width (CJK runes are
// two columns wide) so descriptions stay aligned.
func cleanFlags(s string) string {
	const marker = "[=true|false]"
	lines := strings.Split(strings.ReplaceAll(s, marker, strings.Repeat(" ", len(marker))), "\n")
	for i, l := range lines {
		l = flagType.ReplaceAllStringFunc(l, func(m string) string {
			g := flagType.FindStringSubmatch(m)
			name := typeNames[g[2]]
			pad := len(g[2]) + len(g[3]) - 2*utf8.RuneCountInString(name)
			return g[1] + " " + name + strings.Repeat(" ", max(pad, 1))
		})
		lines[i] = flagDefault.ReplaceAllString(l, "（默认 $1）")
	}
	return strings.Join(lines, "\n")
}
