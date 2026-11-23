# Shared gates come from the published go-standards; see standard.mk.
include standard.mk

CHECK_EXTRA := modverify

.PHONY: modverify build corpus fuzz
modverify:
	$(GO) mod verify

build:
	$(GO) build -o bin/swtele ./cmd/swtele

# Private corpus: real device snapshots kept outside the repository (TST-3).
corpus:
	SWTELE_CORPUS="$(SWTELE_CORPUS)" $(GO) test -count=1 -run '^TestPrivateCorpus$$' -v ./vendors ./vendors/comware ./vendors/nxos ./internal/corpus

fuzz:
	$(GO) test -run '^$$' -fuzz FuzzDecode -fuzztime 30s ./vendors/comware
