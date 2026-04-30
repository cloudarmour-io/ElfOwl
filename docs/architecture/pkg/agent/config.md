# `pkg/agent/config.go` — Configuration Schema & Loading

**Package:** `agent`
**Path:** `pkg/agent/config.go`
**Lines:** ~533
**Added:** Dec 26, 2025

---

## Overview

Defines all configuration structs for the agent and implements:
- `LoadConfig()` — reads YAML from disk, expands sentinel env vars, applies env-var overrides, validates
- `DefaultConfig()` — returns a safe baseline used as the merge target before YAML is parsed
- `expandSentinelVars()` — scoped env expansion (only `OWL_*` and `HOSTNAME`; prevents arbitrary injection)
- `(Config).applyEnvironmentOverrides()` — maps specific `OWL_*` env vars onto struct fields
- `(Config).Validate()` — enforces required fields and catches invalid combinations at startup

---

## Config Loading Pipeline

```
DefaultConfig()         ← Go zero-value safe baseline (all subsystems have working defaults)
       │
       ▼
os.Stat(configPaths[])  ← search order: ./config/elf-owl.yaml → /etc/elf-owl/ → $HOME/.config/
       │
       ▼
os.ReadFile(path)
       │
       ▼
expandSentinelVars()    ← expand only ${HOSTNAME} and ${OWL_*} in the raw YAML bytes
       │
       ▼
yaml.Unmarshal()        ← merges YAML values on top of DefaultConfig() baseline
       │
       ▼
applyEnvironmentOverrides()   ← explicit OWL_* env vars always win over YAML
       │
       ▼
Validate()              ← required fields, node_name fallback, webhook guards, config-combo checks
```

---

## Config File Search Order

| Priority | Path |
|---|---|
| 1 (highest) | `./config/elf-owl.yaml` (relative to working directory) |
| 2 | `/etc/elf-owl/elf-owl.yaml` |
| 3 | `$HOME/.config/elf-owl/elf-owl.yaml` |

The first path that exists wins. If none exist, `DefaultConfig()` values are used after env-var overrides.

---

## Top-Level Struct Tree

```
Config
└── Agent  AgentConfig
    ├── ClusterID    string
    ├── NodeName     string
    ├── Logging      LoggingConfig
    ├── EBPF         EBPFConfig
    │   ├── Process, Network, DNS, File, Capability, TLS  EBPFMonitorConfig
    │   ├── PerfBuffer  PerfBufferConfig
    │   └── RingBuffer  RingBufferConfig
    ├── Kubernetes   KubernetesConfig
    ├── Rules        RulesConfig
    │   └── ConfigMap  struct{ Name, Namespace string }
    ├── Enrichment   EnrichmentConfig
    ├── Evidence     EvidenceConfig
    │   ├── Signing      SigningConfig
    │   └── Encryption   EncryptionConfig
    ├── OWL          OWLConfig
    │   ├── Auth   AuthConfig
    │   ├── Push   PushConfig
    │   ├── Retry  config.RetryConfig
    │   └── TLS    TLSConfig
    ├── Metrics      MetricsConfig
    ├── Health       HealthConfig
    └── Webhook      WebhookConfig
```

---

## Struct Reference

### `Config`

| Field | YAML key | Type | Description |
|---|---|---|---|
| `Agent` | `agent` | `AgentConfig` | All agent settings |

### `AgentConfig`

| Field | YAML key | Default | Description |
|---|---|---|---|
| `ClusterID` | `cluster_id` | `"default"` | Kubernetes cluster identifier; required |
| `NodeName` | `node_name` | `os.Hostname()` | Node the agent runs on; required |
| `Logging` | `logging` | level=info, format=json | Log level/format/output |
| `EBPF` | `ebpf` | all monitors enabled | eBPF subsystem config |
| `Kubernetes` | `kubernetes` | in_cluster=true, TTL=5m | K8s client config |
| `Rules` | `rules` | configmap=elf-owl-rules | Rule loading config |
| `Enrichment` | `enrichment` | kubernetes_only=true | Enrichment pipeline config |
| `Evidence` | `evidence` | HMAC + AES enabled | Evidence signing/encryption |
| `OWL` | `owl_api` | endpoint required | OWL SaaS push config |
| `Metrics` | `metrics` | `:9090/metrics` | Prometheus HTTP server |
| `Health` | `health` | `:9091/health` | Health HTTP server |
| `Webhook` | `webhook` | disabled | Outbound ClickHouse push |

### `EBPFConfig`

| Field | YAML key | Default | Description |
|---|---|---|---|
| `Enabled` | `enabled` | `true` | Master switch for all eBPF monitoring |
| `KernelBTFPath` | `kernel_btf_path` | `""` | Path to custom BTF vmlinux (leave empty for auto-detect) |
| `Process` | `process` | enabled, buf=8192 | Process monitor config |
| `Network` | `network` | enabled, buf=8192 | Network monitor config |
| `DNS` | `dns` | enabled, buf=4096 | DNS monitor config |
| `File` | `file` | enabled, buf=8192 | File monitor config |
| `Capability` | `capability` | enabled, buf=4096 | Capability monitor config |
| `TLS` | `tls` | enabled, buf=4096 | TLS monitor config |
| `PerfBuffer` | `perf_buffer` | enabled, pages=64 | Perf buffer (older kernels) |
| `RingBuffer` | `ring_buffer` | disabled, size=65536 | Ring buffer (kernel 5.8+, preferred) |

### `EBPFMonitorConfig`

| Field | YAML key | Description |
|---|---|---|
| `Enabled` | `enabled` | Enable/disable this monitor |
| `BufferSize` | `buffer_size` | Event channel capacity (events) |
| `Timeout` | `timeout` | Read timeout per event |

### `EnrichmentConfig`

| Field | YAML key | Default | Description |
|---|---|---|---|
| `KubernetesMetadata` | `kubernetes_metadata` | `true` | Enable K8s API enrichment; set false for VM/no-k8s |
| `MetadataCacheSize` | `metadata_cache_size` | `10000` | LRU cache capacity |
| `MetadataCacheTTL` | `metadata_cache_ttl` | `1m` | Cache entry TTL |
| `KubernetesOnly` | `kubernetes_only` | `true` | Discard events with no pod context |

**Critical combination guard:** `kubernetes_metadata=false` + `kubernetes_only=true` is rejected at `Validate()` time — it would discard every event.

### `OWLConfig`

| Field | YAML key | Description |
|---|---|---|
| `Endpoint` | `endpoint` | OWL SaaS HTTPS endpoint; **required** |
| `Auth.Method` | `auth.method` | `"jwt"` |
| `Auth.TokenPath` | `auth.token_path` | JWT token file (default: `/var/run/secrets/owl-jwt-token`) |
| `Push.BatchSize` | `push.batch_size` | Events per push batch (default: 100) |
| `Push.BatchTimeout` | `push.batch_timeout` | Max time between flushes (default: 30s) |
| `Push.Enabled` | `push.enabled` | Gate for push goroutine (default: true) |
| `Push.DryRun` | `push.dry_run` | Log instead of pushing (default: false) |
| `Retry.*` | `retry.*` | Exponential backoff config (max=10, initial=1s, max=60s) |
| `TLS.*` | `tls.*` | Custom CA, mTLS cert/key for OWL API |

### `WebhookConfig`

| Field | YAML key | Default | Description |
|---|---|---|---|
| `Enabled` | `enabled` | `false` | Enable outbound ClickHouse push |
| `TargetURL` | `target_url` | `""` | HTTP POST endpoint; required when enabled |
| `BatchSize` | `batch_size` | `100` | Events per POST batch |
| `FlushInterval` | `flush_interval` | `5s` | Max time between flushes |
| `Timeout` | `timeout` | `10s` | HTTP request timeout |
| `Headers` | `headers` | `{}` | Custom headers (e.g., `Authorization`) |
| `TLSCAPath` | `tls_ca_path` | `""` | Custom CA cert PEM (appended to system pool) |
| `TLSCertPath` | `tls_cert_path` | `""` | Client cert for mTLS |
| `TLSKeyPath` | `tls_key_path` | `""` | Client key for mTLS |

---

## Functions

### `expandSentinelVars(s string) string`

Scoped variable expansion — replaces only `$HOSTNAME`, `${HOSTNAME}`, and `$OWL_*` / `${OWL_*}` patterns in the YAML string.

**Why scoped?** Prior implementation used `os.ExpandEnv()` which expanded every `$VAR` in the file, enabling arbitrary env injection from YAML values (e.g., rule condition strings). Bug #8 (Apr 30, 2026).

**HOSTNAME fallback:** `sudo` strips `HOSTNAME` (a bash internal) from the child environment. When `HOSTNAME` is absent from `os.Environ()`, the function calls `os.Hostname()` (a syscall) as a reliable alternative.

### `LoadConfig() (*Config, error)`

Loads and validates configuration. Returns error on:
- File read/parse failure
- Validation failure (missing required fields, invalid combinations)

### `(c *Config) applyEnvironmentOverrides()`

Maps environment variables to config fields. All overrides use the `OWL_` prefix (except `HOSTNAME`).

| Env var | Config field |
|---|---|
| `OWL_CLUSTER_ID` | `Agent.ClusterID` |
| `OWL_NODE_NAME` | `Agent.NodeName` |
| `OWL_API_ENDPOINT` | `Agent.OWL.Endpoint` |
| `OWL_LOG_LEVEL` | `Agent.Logging.Level` |
| `OWL_K8S_IN_CLUSTER` | `Agent.Kubernetes.InCluster` (bool) |
| `OWL_KUBERNETES_ONLY` | `Agent.Enrichment.KubernetesOnly` (bool) |
| `OWL_KUBERNETES_METADATA` | `Agent.Enrichment.KubernetesMetadata` (bool) |
| `OWL_WEBHOOK_ENABLED` | `Agent.Webhook.Enabled` (bool) |
| `OWL_WEBHOOK_TARGET_URL` | `Agent.Webhook.TargetURL` |

### `(c *Config) Validate() error`

Validation rules:

| Check | Error |
|---|---|
| `ClusterID == ""` | required |
| `NodeName == ""` after fallbacks | required (fallback: `HOSTNAME` env → `os.Hostname()`) |
| `OWL.Endpoint == ""` | required |
| `Webhook.Enabled && TargetURL == ""` | target URL required |
| `Webhook.Enabled && BatchSize < 0` | must be ≥ 0 |
| `Webhook.Enabled && FlushInterval < 0` | must be ≥ 0 |
| `!KubernetesMetadata && KubernetesOnly` | would discard all events |

`OWL.Auth.TokenPath` is defaulted to `/var/run/secrets/owl-jwt-token` if empty.

### `DefaultConfig() *Config`

Returns a complete, deployable configuration baseline. Key defaults:

| Setting | Default |
|---|---|
| All eBPF monitors | enabled |
| Ring buffer | disabled (perf buffer preferred for compatibility) |
| K8s WatchInterval | 0 (no resync — prevents compliance event storms) |
| Enrichment.KubernetesOnly | `true` |
| Evidence signing | HMAC-SHA256, enabled |
| Evidence encryption | AES-256-GCM, enabled |
| OWL push batch | 100 events, 30 s timeout |
| OWL retry | 10 retries, 1s→60s exponential |
| Metrics | `:9090/metrics` |
| Health | `:9091/health` |
| Webhook | disabled |

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 19–23 | `expandSentinelVars` — scoped expansion preventing YAML injection (Bug #8) |
| 23 | HOSTNAME fallback for sudo environments |
| 64 | `AgentConfig` — cilium/ebpf migration note |
| 149 | `kubernetes_only` flag — semantics of host event discard |
| 219 | `WebhookConfig` — added Apr 29 for ClickHouse push |
| 230 | `WebhookConfig` TLS fields — safe default (system CA, no mTLS) |
| 247 | Defaults-first loading — prevents zero-values for new config blocks |
| 261 | `expandSentinelVars` call site explanation |
| 304 | K8s mode override via env — for VM/local testing |
| 346 | `node_name` fallback chain — HOSTNAME absent under sudo |
| 371 | Webhook target URL guard — enabled with no URL silently drops events |
| 376 | BatchSize/FlushInterval validation — clear startup error vs silent clamp |
| 386 | `kubernetes_metadata+kubernetes_only` guard — prevents all-events discard |
| 458 | K8s WatchInterval default 0 — prevents informer resync storms |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/agent/agent.go](./agent.md) | Calls `LoadConfig()`, `DefaultConfig()`; uses all config structs |
| [pkg/config/types.go](../config/) | `config.RetryConfig` embedded in `OWLConfig.Retry` |
| [config/elf-owl.yaml](../../../../config/elf-owl.yaml) | Default YAML config file read by `LoadConfig()` |
