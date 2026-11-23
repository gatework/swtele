package oui_test

import (
	"strings"
	"testing"

	"github.com/gatework/swtele/adapter/oui"
)

func TestRead(t *testing.T) {
	t.Parallel()
	const reg = `OUI/MA-L                                                    Organization
company_id                                                  Organization
                                                            Address

00-00-5E   (hex)		ICANN, IANA Department
00005E     (base 16)		ICANN, IANA Department
				Los Angeles CA 90094
AA-BB-CC   (hex)		Example Networks
`
	m, err := oui.Read(strings.NewReader(reg))
	if err != nil || len(m) != 2 || m["00:00:5e"] != "ICANN, IANA Department" || m["aa:bb:cc"] != "Example Networks" {
		t.Errorf("read %v %v", m, err)
	}
}
