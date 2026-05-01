# Architecture Documentation

Per-directory and per-file reference documentation for the `elf-owl` codebase.

---

## Structure

Each subdirectory here mirrors the source tree. Every source file has a corresponding `.md` document.

```
docs/architecture/
├── README.md                  ← this file
└── cmd/
    └── elf-owl/
        ├── README.md          ← directory overview
        └── main.md            ← cmd/elf-owl/main.go
```

---

## Coverage

| Source path | Doc path | Status |
|---|---|---|
| `cmd/elf-owl/main.go` | [cmd/elf-owl/main.md](cmd/elf-owl/main.md) | ✅ Done |
| `pkg/agent/agent.go` | [pkg/agent/agent.md](pkg/agent/agent.md) | ✅ Done |
| `pkg/agent/config.go` | [pkg/agent/config.md](pkg/agent/config.md) | ✅ Done |
| `pkg/agent/webhook.go` | [pkg/agent/webhook.md](pkg/agent/webhook.md) | ✅ Done |
| `pkg/agent/compliance_watcher.go` | [pkg/agent/compliance_watcher.md](pkg/agent/compliance_watcher.md) | ✅ Done |
| `pkg/api/client.go` | [pkg/api/client.md](pkg/api/client.md) | ✅ Done |
| `pkg/api/tls_certificate.go` | [pkg/api/tls_certificate.md](pkg/api/tls_certificate.md) | ✅ Done |
| `pkg/config/types.go` | [pkg/config/types.md](pkg/config/types.md) | ✅ Done |
| `pkg/ebpf/types.go` | [pkg/ebpf/types.md](pkg/ebpf/types.md) | ✅ Done |
| `pkg/ebpf/loader.go` | [pkg/ebpf/loader.md](pkg/ebpf/loader.md) | ✅ Done |
| `pkg/ebpf/bytecode_embed.go` | [pkg/ebpf/bytecode_embed.md](pkg/ebpf/bytecode_embed.md) | ✅ Done |
| `pkg/ebpf/*_monitor.go` (×5) | [pkg/ebpf/monitors.md](pkg/ebpf/monitors.md) | ✅ Done |
| `pkg/ebpf/tls_monitor.go` | [pkg/ebpf/tls_monitor.md](pkg/ebpf/tls_monitor.md) | ✅ Done |
| `pkg/ebpf/ja3.go` | [pkg/ebpf/ja3.md](pkg/ebpf/ja3.md) | ✅ Done |
| `pkg/ebpf/programs/Makefile` | [pkg/ebpf/programs/Makefile.md](pkg/ebpf/programs/Makefile.md) | ✅ Done |
| `pkg/ebpf/programs/common.h` | [pkg/ebpf/programs/common_h.md](pkg/ebpf/programs/common_h.md) | ✅ Done |
| `pkg/ebpf/programs/process.c` | [pkg/ebpf/programs/process_c.md](pkg/ebpf/programs/process_c.md) | ✅ Done |
| `pkg/ebpf/programs/network.c` | [pkg/ebpf/programs/network_c.md](pkg/ebpf/programs/network_c.md) | ✅ Done |
| `pkg/ebpf/programs/dns.c` | [pkg/ebpf/programs/dns_c.md](pkg/ebpf/programs/dns_c.md) | ✅ Done |
| `pkg/ebpf/programs/file.c` | [pkg/ebpf/programs/file_c.md](pkg/ebpf/programs/file_c.md) | ✅ Done |
| `pkg/ebpf/programs/capability.c` | [pkg/ebpf/programs/capability_c.md](pkg/ebpf/programs/capability_c.md) | ✅ Done |
| `pkg/ebpf/programs/tls.c` | [pkg/ebpf/programs/tls_c.md](pkg/ebpf/programs/tls_c.md) | ✅ Done |
| `pkg/ja3/parser.go` | [pkg/ja3/parser.md](pkg/ja3/parser.md) | ✅ Done |
| `pkg/enrichment/types.go` | [pkg/enrichment/types.md](pkg/enrichment/types.md) | ✅ Done |
| `pkg/enrichment/enricher.go` + `errors.go` | [pkg/enrichment/enricher.md](pkg/enrichment/enricher.md) | ✅ Done |
| `pkg/evidence/signer.go` | [pkg/evidence/signer.md](pkg/evidence/signer.md) | ✅ Done |
| `pkg/evidence/cipher.go` | [pkg/evidence/cipher.md](pkg/evidence/cipher.md) | ✅ Done |
| `pkg/evidence/buffer.go` | [pkg/evidence/buffer.md](pkg/evidence/buffer.md) | ✅ Done |
| `pkg/kubernetes/client.go` | [pkg/kubernetes/client.md](pkg/kubernetes/client.md) | ✅ Done |
| `pkg/kubernetes/cache.go` | [pkg/kubernetes/cache.md](pkg/kubernetes/cache.md) | ✅ Done |
| `pkg/kubernetes/pod_fields.go` | [pkg/kubernetes/pod_fields.md](pkg/kubernetes/pod_fields.md) | ✅ Done |
| `pkg/metrics/prometheus.go` | [pkg/metrics/prometheus.md](pkg/metrics/prometheus.md) | ✅ Done |
| `pkg/logger/logger.go` | [pkg/logger/logger.md](pkg/logger/logger.md) | ✅ Done |
| `pkg/rules/engine.go` | [pkg/rules/engine.md](pkg/rules/engine.md) | ✅ Done |
| `pkg/rules/cis_mappings.go` | [pkg/rules/cis_mappings.md](pkg/rules/cis_mappings.md) | ✅ Done |
| `pkg/rules/loader.go` | [pkg/rules/loader.md](pkg/rules/loader.md) | ✅ Done |
