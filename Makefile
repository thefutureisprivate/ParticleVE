PYTHON ?= python3
RUFF ?= ruff
export PYTHONPATH := $(CURDIR)/Sources:$(CURDIR)

.PHONY: check test lint sources check-upstream summary
check: lint test
	$(PYTHON) Tools/version.py check

test:
	$(PYTHON) -W error -m unittest discover -v

lint:
	$(RUFF) check . .obs/mkosi/mkosi-entrypoint.py
	$(RUFF) format --check . .obs/mkosi/mkosi-entrypoint.py
	for script in mkosi.postinst.chroot \
		mkosi.finalize \
		mkosi.profiles/particleve/mkosi.postinst.chroot \
		mkosi.profiles/particleve/mkosi.finalize \
		mkosi.initrd.conf/mkosi.postinst \
		mkosi.initrd.conf/mkosi.finalize \
		mkosi.initrd.conf/mkosi.extra/usr/libexec/particleve-initrd-storage \
		mkosi.extra/usr/lib/systemd/system-shutdown/particleve-storage \
		Tests/acceptance/build-loader-probe.sh; do \
		bash -n "$$script" || exit "$$?"; \
	done

sources:
	$(PYTHON) Tools/fetch-sources.py

check-upstream: sources
	$(PYTHON) Tools/check-upstream.py

summary:
	mkdir -p build
	build/sources/mkosi/bin/mkosi --json summary > build/summary.json
	$(PYTHON) Tools/check-build.py --summary build/summary.json
