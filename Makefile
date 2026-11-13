PYTHON ?= python3
RUFF ?= ruff
CARGO ?= cargo
RUSTFLAGS ?= -Dwarnings -Ctarget-cpu=x86-64-v2 -Cforce-frame-pointers=yes -Clink-arg=-Wl,-z,relro,-z,now
export RUSTFLAGS
RUNTIME_TARGET_DIR := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)
export PYTHONPATH := $(CURDIR)/Sources:$(CURDIR)

.PHONY: check test lint rust-check sources check-upstream summary
check: lint test
	$(PYTHON) Tools/version.py check

test:
	$(CARGO) test --locked
	$(CARGO) build --locked --example runtime-contract-driver
	PVE_RUNTIME_DRIVER=$(RUNTIME_TARGET_DIR)/debug/examples/runtime-contract-driver $(PYTHON) -W error -m unittest discover -v

lint: rust-check
	$(RUFF) check . .obs/mkosi/mkosi-entrypoint.py
	$(RUFF) format --check . .obs/mkosi/mkosi-entrypoint.py
	for script in mkosi.postinst.chroot \
		mkosi.finalize \
		mkosi.profiles/particleve/mkosi.postinst.chroot \
		mkosi.profiles/particleve/mkosi.finalize \
		mkosi.initrd.conf/mkosi.postinst \
		mkosi.initrd.conf/mkosi.finalize \
		Tests/acceptance/build-loader-probe.sh; do \
		bash -n "$$script" || exit "$$?"; \
	done

rust-check:
	$(CARGO) fmt -- --check
	$(CARGO) clippy --locked --all-targets -- -D warnings

sources:
	$(PYTHON) Tools/fetch-sources.py

check-upstream: sources
	$(PYTHON) Tools/check-upstream.py

summary:
	mkdir -p build
	build/sources/mkosi/bin/mkosi --json summary > build/summary.json
	$(PYTHON) Tools/check-build.py --summary build/summary.json
	$(PYTHON) Tools/obs-project.py --site .obs/site.json --summary build/summary.json --check
