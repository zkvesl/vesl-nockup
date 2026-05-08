# vesl-nockup — Makefile
#
# Convenience targets. CI runs the same commands directly.

.PHONY: help graft-inject

help:
	@echo "vesl-nockup — convenience targets"
	@echo ""
	@echo "Targets:"
	@echo "  graft-inject   Rebuild + install tools/graft-inject from current src/"
	@echo "                 (drops the staleness warning until src/ changes again)"

graft-inject:
	cargo install --path tools/graft-inject --force
