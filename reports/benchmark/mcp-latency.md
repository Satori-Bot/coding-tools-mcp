# MCP Runtime Latency Benchmark

- Conclusion: **PASS**
- Endpoint: `http://127.0.0.1:52187/mcp`
- Iterations: `8`
- Exec iterations: `4`
- Warmup iterations: `2`
- Max MCP p95 threshold: `5000 ms`

## Metrics

| metric | samples | min ms | p50 ms | p95 ms | max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| `mcp.tools_list` | 8 | 1.569 | 1.757 | 1.896 | 1.927 |
| `mcp.read_file` | 8 | 1.066 | 1.125 | 1.264 | 1.266 |
| `mcp.search_text` | 8 | 6.371 | 6.579 | 6.827 | 6.841 |
| `mcp.exec_command` | 4 | 22.828 | 22.893 | 22.947 | 22.95 |
| `native.read_text` | 8 | 0.011 | 0.013 | 0.015 | 0.015 |
| `native.search` | 8 | 4.217 | 4.368 | 4.531 | 4.593 |
| `native.exec_command` | 4 | 1.046 | 2.147 | 2.162 | 2.162 |

## Native Baseline Comparison

| operation | MCP p95 ms | native p95 ms | ratio |
| --- | ---: | ---: | ---: |
| `read_file` | 1.264 | 0.015 | 84.267 |
| `search_text` | 6.827 | 4.531 | 1.507 |
| `exec_command` | 22.947 | 2.162 | 10.614 |

## Failures

No failures recorded.

## Notes

- Native baselines are local developer-tool primitives, not equivalent MCP substitutes.
- Latency thresholds are intentionally broad; this smoke benchmark catches transport regressions and records trend evidence.
