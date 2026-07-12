# AMR Workspace

This directory is the canonical staging area for the final AMR package.

## Goal

`experiment_runs/` contains many exploratory and intermediate runs. `amr/` is for the
small final subset that will actually back the AMR submission.

## Layout

- `final_runs/`
  - `handover/` — final preserved handover runs
  - `degradation/` — final preserved degradation runs
  - `stream_aux/` — optional stream/preview-only supporting evidence
- `statistics/`
  - `raw_qlogs/` — staged `qlogs_client/*_{events,snap}.csv`
  - `summary/` — human-maintained final tables derived from staged qlogs
- `docs/`
  - `final_run_set.md` — curated final run table
  - `final_submission_notes.md` — AMR-facing narrative notes
- `manifests/`
  - `final_runs.csv` — machine-readable record of staged final runs
  - `qlog_runs.csv` — machine-readable record of staged qlog CSVs
  - `statistics_summary.csv` — human-maintained summary table for final claims

## Recommended workflow

1. Prepare the workspace:
   - `bash scripts/amr_prepare_workspace.sh`
2. Stage canonical final run artifacts:
   - `bash scripts/amr_stage_run.sh handover <run-id>`
   - `bash scripts/amr_stage_run.sh degradation <run-id>`
3. Stage qlog CSVs used for repeated-experiment/statistical claims:
   - `bash scripts/amr_stage_qlogs.sh <run-prefix-or-run-id> ...`
4. Fill in:
   - `amr/docs/final_run_set.md`
   - `amr/docs/final_submission_notes.md`
   - `amr/manifests/statistics_summary.csv`
5. Validate the package:
   - `bash scripts/amr_validate_package.sh`

If `amr_validate_package.sh` reports failures, do not raise AMR yet.
