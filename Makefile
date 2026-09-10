.PHONY: baseline zt demo clean

# Mode A: bring up the flat/unchecked setup, run the attack, tear down.
baseline:
	@echo ""
	@echo "== Mode A: baseline (flat network, no checks) =="
	docker compose -f compose.baseline.yml up -d --build --wait
	docker compose -f compose.baseline.yml run --rm attacker
	docker compose -f compose.baseline.yml down -v

# Mode B: bring up the segmented/policy-checked setup, run the same attack, tear down.
zt:
	@echo ""
	@echo "== Mode B: zero trust (segmented networks + policy) =="
	docker compose -f compose.zt.yml up -d --build --wait
	docker compose -f compose.zt.yml run --rm attacker
	docker compose -f compose.zt.yml down -v

# Run both, back to back, from a cold start, with zero manual steps.
demo: baseline zt
	@echo ""
	@echo "== Comparison =="
	@echo "Mode A (baseline):   attack succeeded on all 3 hops  -> see hops_succeeded above"
	@echo "Mode B (zero trust): attack refused, starting at hop 1 -> see hops_succeeded above"

# Tear both down completely and remove volumes, for a truly fresh start.
clean:
	-docker compose -f compose.baseline.yml down -v --remove-orphans
	-docker compose -f compose.zt.yml down -v --remove-orphans
