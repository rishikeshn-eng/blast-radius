# Benchmarks

Three independent corpora. Everything here is reproducible from the raw sources.

| corpus | what | n | source |
|---|---|---|---|
| **gold** | hand-labelled commands for precision/recall | 100 | `bench/gold.py` |
| **SWE-agent** | every shell command from real agent trajectories | 55,560 | [nebius/SWE-agent-trajectories](https://huggingface.co/datasets/nebius/SWE-agent-trajectories) |
| **NL2Bash** | human-written one-liners (robustness) | 12,607 | [TellinaTool/nl2bash](https://github.com/TellinaTool/nl2bash) |

## Reproduce

```bash
pip install -r requirements-bench.txt

# 1. gold precision/recall (no download needed)
python bench/eval_gold.py

# 2. real agent commands
#    download the parquet once:
curl -L -o rawdata/swe_traj/part0.parquet \
  https://huggingface.co/datasets/nebius/SWE-agent-trajectories/resolve/main/data/train-00000-of-00012.parquet
python bench/extract.py rawdata/swe_traj/part0.parquet bench/out/swe_cmds.jsonl
python bench/run_bench.py bench/out/swe_cmds.jsonl swe_agent bench/out

# 3. NL2Bash robustness
curl -L -o rawdata/nl2bash/all.cm \
  https://raw.githubusercontent.com/TellinaTool/nl2bash/master/data/bash/all.cm
python bench/run_bench.py rawdata/nl2bash/all.cm nl2bash bench/out
```

## Headline results (see `bench/out/report.json`)

**Gold set (100 commands)**
- Exact-match accuracy: **97%**
- Block precision / recall / F1: **0.91 / 1.00 / 0.95**
- Dangerous commands rated too softly: **0**. Every error is the tool being
  *one tier more cautious* than the human label, never less.

**55,560 real agent commands**
- Verdicts: 95.4% allow · 4.2% review · 0.39% block
- Parser handled 99.55% of inputs cleanly (the rest degrade to `review`)
- Mean / p99 latency: **0.028 ms / 0.14 ms** per command, single core, no model calls
- Commands rated `block` appear **25.5×** more often in trajectories that
  *failed* their task than in those that solved it — destructive flailing is a
  signal of a run going wrong.

**NL2Bash (12,607 human commands)**
- Verdicts: 70.1% allow · 26.8% review · 3.2% block (humans deliberately write
  more `sudo`, `find -exec`, `chown` and network commands than agents do)
- Parse-failure rate: 0.46%

Zero analyzer crashes across all 68,167 inputs.
