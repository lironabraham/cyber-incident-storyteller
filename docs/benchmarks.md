# Performance Benchmarks

All numbers measured on a single core (no parallelism) against a synthetic
`auth.log` where every unique IP generates 10 failed logins followed by 1
accepted login — the worst-case pattern for the hunter because every IP
crosses the brute-force threshold and produces a real attack chain.

## Results

| Lines | Events | Chains | Time (s) | Lines/s | Peak MB |
|------:|-------:|-------:|---------:|--------:|--------:|
| 500   | 500    | 46     | 1.109    | 450     | 3.2     |
| 1,000 | 1,000  | 91     | 3.205    | 311     | 6.3     |
| 5,000 | 5,000  | 455    | 50.720   | 98      | 39.7    |

## Reproduce locally

```bash
py tests/benchmarks/bench_pipeline.py
```

No extra dependencies — uses only the stdlib (`tracemalloc`, `time`) and the
`src/` modules already installed by `pip install ais-storyteller`.

## Scaling characteristics

The current implementation is **O(n²)** in the hunter pivot engine.
For each attacker IP flagged in the trigger pass, a second full scan of the
event list builds the complete attack chain. As chain count grows, the cost
compounds: at 5,000 lines the pipeline processes ~98 lines/s, roughly 4.5×
slower than at 500 lines.

This is by design for Phase 1 (single-host, analyst-driven): real auth logs
rarely exceed a few thousand lines in a single investigation, and the absolute
time remains well under a minute for those sizes.

!!! note "Phase 3 roadmap"
    Fleet-scale ingestion (millions of events across thousands of hosts) will
    replace the in-memory pivot scan with a NetworkX → Neo4j graph query.
    That work is tracked in the Phase 3 roadmap milestone.

## Memory

Peak heap scales linearly with event count — the entire event list is held in
memory as a `list[StandardEvent]` during correlation. At 5,000 events the
overhead is ~40 MB; a 50,000-event log would require ~400 MB. For single-host
DFIR this is acceptable; fleet-scale streaming ingestion is a Phase 3 concern.
