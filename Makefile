# fixproof: build hosts in known states, scan them, compare with the truth.
# Needs Docker, uv, and network access to archive.ubuntu.com, snapshot.ubuntu.com, Docker Hub
# (or mirror.gcr.io), mirror.gcr.io/aquasec/trivy-db and the OSV bucket. See docs/reproduce.md.
UV ?= uv
REPEATS ?= 3

.PHONY: setup tools feeds lab run score report charts test lint reproduce rescore clean

setup:
	$(UV) sync --all-extras

tools:            ## osv-scanner 2.7.1 and vuls 0.42.0 built from the Go module proxy into .tools/
	lab/tools/build_tools.sh

feeds:            ## trivy DB (frozen afterwards) and the filtered OSV database
	lab/tools/fetch_feeds.sh
	$(UV) run python lab/tools/osv_filter.py

lab:              ## Ubuntu lab images; official images pulled; digests to results/lab_images.json
	$(UV) run fixproof images --build

run:              ## every host state x $(REPEATS) repeats (skips runs already in results/raw)
	$(UV) run fixproof run --repeats $(REPEATS)

score:
	$(UV) run fixproof score

report: score
	$(UV) run fixproof report

charts: report
	$(UV) run fixproof charts

test:
	$(UV) run pytest -q

lint:
	$(UV) run ruff check src tests lab

reproduce: setup tools feeds lab run charts test   ## rebuild every committed result from scratch

rescore: setup score report charts test             ## recompute tables and charts from committed raw data

clean:
	docker ps -aq --filter name=fp- | xargs -r docker rm -f
	rm -rf work
