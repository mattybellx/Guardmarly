# Performance

## v5.0.0 Speed Improvements

| Optimization | Impact |
|-------------|--------|
| AST walk cache (49 rules share node lists) | +11% |
| `_rule_24` fix (1 walk instead of 20x) | +38% |
| Lazy symbolic guards | +17% |
| Lazy datascience rules | +10% |
| **Total Python improvement** | **+96%** (2,600→5,100 LOC/s) |

## Rust Pattern Engine

JavaScript pattern rules execute 3.6x faster on large files via the native Rust regex engine (`ansede_rust_core`). The engine gracefully falls back to Python for complex patterns (look-around regexes, context_confirm filters).

| File Size | Python | Rust+Python | Speedup |
|-----------|--------|-------------|---------|
| 283 lines | 14ms | 22ms | 0.6x (overhead) |
| 60k lines | 1,972ms | **547ms** | **3.6x** |

## 21-Repo Speed Loop

| Repo | Lang | Files | Lines | Time | LOC/s |
|------|------|-------|-------|------|-------|
| p_flask | Python | 83 | 18,337 | 24s | 764 |
| s_microblog | Python | 34 | 1,843 | 4s | 461 |
| s3_requests | Python | 37 | 12,032 | 16s | 752 |
| p_express | JS | 139 | 21,424 | 12s | 1,785 |
| s_keystone | JS | 739 | 62,403 | 43s | 1,451 |
| s3_lodash | JS | 25 | 6,479 | 25s | 259 |
| s3_axios | JS | 227 | 35,900 | 19s | 1,889 |
| p_petclinic | Java | 47 | 3,796 | 1s | 3,796 |
| s3_gson | Java | 262 | 55,620 | 7s | 7,946 |
| p_cleanarch | C# | 364 | 11,833 | 4s | 2,958 |
| s3_automapper | C# | 512 | 65,052 | 6s | 10,842 |
| s3_mediatr | C# | 152 | 11,389 | 2s | 5,695 |
| p_gin | Go | 99 | 8,196 | 2s | 4,098 |
| s3_cobra | Go | 36 | 6,955 | 1s | 6,955 |
| s3_viper | Go | 33 | 3,513 | 1s | 3,513 |
| s3_sinatra | Ruby | 150 | 24,038 | 3s | 8,013 |
| s3_rake | Ruby | 96 | 13,156 | 1s | 13,156 |
| s3_faker | Ruby | 570 | 39,019 | 6s | 6,503 |
| s3_slim | PHP | 124 | 16,300 | 2s | 8,150 |
| s3_monolog | PHP | 217 | 28,278 | 3s | 9,426 |
| s3_carbon | PHP | 2004 | 331,925 | 27s | 12,293 |

**Total: 5,950 files, 777k lines scanned in ~208 seconds (~3,700 LOC/s average)**

## Profiling Data

Pre-optimization profile (models.py, 1,184 lines):

| Function | Time | % |
|----------|------|---|
| `ast.walk()` | 1.2s | 60% |
| `_rule_24` (JWT) | 0.73s | 36% |
| `symbolic_guards` | 0.33s | 16% |
| `_rule_03` | 0.16s | 8% |

Post-optimization: `ast.walk()` reduced 45%, `_rule_24` eliminated as bottleneck, symbolic guards skipped for simple files.
