# dryfire build targets. Run `make all` for the full CI pipeline.

PYTHON ?= python3
RULES  := rules

# Zircolite runs the Sigma rules against log samples in `make test`.
# It's not on PyPI, so we download a pinned release binary and check its hash.
# Hashes come from the release's SHA256SUMS file.
ZIRCOLITE_VERSION := 4.5.0
ZIRCOLITE_DIR     := tools/zircolite
ZIRCOLITE         := $(ZIRCOLITE_DIR)/Zircolite

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S)-$(UNAME_M),Linux-x86_64)
  ZIRCOLITE_PLATFORM := linux-x64
  ZIRCOLITE_SHA256   := 07c72bcfb4303a61abfde562b0e18010c42414a125239db980c0e42f5144755a
else ifeq ($(UNAME_S)-$(UNAME_M),Linux-aarch64)
  ZIRCOLITE_PLATFORM := linux-arm64
  ZIRCOLITE_SHA256   := ec0e0cd56d49fa855f45ca55c9f61f897cad9b1991586ff0c55b77d4421f12af
else ifeq ($(UNAME_S)-$(UNAME_M),Darwin-arm64)
  ZIRCOLITE_PLATFORM := macos-arm64
  ZIRCOLITE_SHA256   := 984a13f2c8aa9b214716778ac4aeb36b1be72638f2983349c0996eb8b813077f
endif
ZIRCOLITE_ZIP := Zircolite-$(ZIRCOLITE_VERSION)-$(ZIRCOLITE_PLATFORM).zip
ZIRCOLITE_URL := https://github.com/wagga40/Zircolite/releases/download/v$(ZIRCOLITE_VERSION)/$(ZIRCOLITE_ZIP)

.PHONY: all lint convert test coverage datasets zircolite clean

all: lint convert test coverage

# Validate every rule with `sigma check`, using a pinned ATT&CK version
# (see scripts/lint.py). --fail-on-issues makes validator warnings fail the build too.
# Extra flags can be passed in, e.g. make lint LINT_FLAGS="-x d3_fendtag"
lint:
	$(PYTHON) scripts/lint.py --fail-on-issues $(LINT_FLAGS) $(RULES)

# Sigma -> SPL and KQL, written to build/.
convert:
	$(PYTHON) scripts/convert.py --rules-dir $(RULES)

# Run every rule against its positive and negative samples.
test: datasets $(ZIRCOLITE)
	$(PYTHON) tests/run_tests.py --rules-dir $(RULES) --zircolite $(ZIRCOLITE)

# ATT&CK Navigator layer from the rule tags.
coverage:
	$(PYTHON) scripts/coverage.py --rules-dir $(RULES)

# Download the public datasets listed in tests/datasets.yml.
datasets:
	$(PYTHON) scripts/fetch_datasets.py

zircolite: $(ZIRCOLITE)

$(ZIRCOLITE):
ifndef ZIRCOLITE_PLATFORM
	$(error No pinned Zircolite build for $(UNAME_S) $(UNAME_M). Install it yourself and run tests/run_tests.py --zircolite <path>)
endif
	mkdir -p tools
	curl -fsSL -o tools/$(ZIRCOLITE_ZIP) $(ZIRCOLITE_URL)
	echo "$(ZIRCOLITE_SHA256)  tools/$(ZIRCOLITE_ZIP)" | shasum -a 256 -c -
	rm -rf $(ZIRCOLITE_DIR) tools/Zircolite-$(ZIRCOLITE_VERSION)-$(ZIRCOLITE_PLATFORM)
	cd tools && unzip -q $(ZIRCOLITE_ZIP)
	mv tools/Zircolite-$(ZIRCOLITE_VERSION)-$(ZIRCOLITE_PLATFORM) $(ZIRCOLITE_DIR)
	rm tools/$(ZIRCOLITE_ZIP)

clean:
	rm -rf build
