# `pkg/rules/cis_mappings.go` — Hardcoded CIS Controls

**Package:** `rules`
**Path:** `pkg/rules/cis_mappings.go`
**Lines:** 753

---

## Overview

Defines `CISControls`, the `[]*Rule` slice returned by `loadCISRules()` as the last fallback in `NewEngineWithConfig`. Contains all 47 hardcoded runtime-detectable CIS Kubernetes v1.8 control definitions. No logic — pure data.

---

## `var CISControls []*Rule`

All rules follow the same structure: `ControlID`, `Title`, `Severity`, one or more `EventTypes`, and one or more `Conditions` (AND semantics).

---

## Rules by Category

### Legacy Pod Security (CIS 4.5.x) — 4 rules

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_4.5.1` | CRITICAL | `process_execution`, `pod_spec_check` | `container.security_context.privileged == true` |
| `CIS_4.5.2` | HIGH | `process_execution` | `process.uid == 0` AND `kubernetes.pod_uid != ""` |
| `CIS_4.5.3` | HIGH | `capability_usage` | `capability.name in [SYS_MODULE, SYS_BOOT, SYS_TIME, SYS_RAWIO, SYS_PACCT]` |
| `CIS_4.5.5` | MEDIUM | `file_access` ¹ | `file.path in [/, /bin, /sbin, /usr/bin, /usr/sbin, /etc, /lib, /usr/lib]` |

¹ **Bug fix (Feb 18, 2026):** was `file_write`. FileMonitor emits `file_access` — the wrong event type meant this rule never fired.

### ServiceAccount (legacy) — 1 rule

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_4.1.1` | HIGH | `pod_spec_check` | `kubernetes.service_account == "default"` |

### Network Policy — 5 rules

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_4.6.1` | HIGH | `network_connection`, `network_policy_check` ² | `kubernetes.has_default_deny_policy != true` |
| `CIS_4.6.2` | HIGH | `network_connection` | `network.ingress_restricted == false` |
| `CIS_4.6.3` | HIGH | `network_connection` | `network.egress_restricted == false` |
| `CIS_4.6.4` | MEDIUM | `dns_query` | `dns.query_allowed == false` |
| `CIS_4.6.5` | HIGH | `network_connection` | `network.namespace_isolation == false` |

² **Bug fix (Feb 18, 2026):** `network_connection` added alongside `network_policy_check`. The enricher sets `kubernetes.has_default_deny_policy` on every `network_connection` event; `network_policy_check` was a placeholder for a future K8s API polling path.

### Pod Security Context (CIS 4.2.x) — 8 rules

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_4.2.1` | HIGH | `process_execution` | `container.run_as_root == true` |
| `CIS_4.2.2` | HIGH | `process_execution`, `capability_usage` | `container.allow_privilege_escalation == true` |
| `CIS_4.2.3` | HIGH | `network_connection` | `container.host_network == true` |
| `CIS_4.2.4` | HIGH | `process_execution` | `container.host_ipc == true` |
| `CIS_4.2.5` | HIGH | `process_execution` | `container.host_pid == true` |
| `CIS_4.2.6` | HIGH | `capability_usage` | `capability.name in [NET_ADMIN, NET_RAW, SYS_ADMIN, SYS_PTRACE, MAC_ADMIN, MAC_OVERRIDE, DAC_OVERRIDE, DAC_READ_SEARCH, SETFCAP]` |
| `CIS_4.2.7` | MEDIUM | `process_execution` | `container.seccomp_profile == "unconfined"` |
| `CIS_4.2.8` | MEDIUM | `process_execution` | `container.apparmor_profile == "unconfined"` |

### Container Image & Registry (CIS 4.3.x) — 6 rules

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_4.3.1` | MEDIUM | `pod_spec_check` | `kubernetes.image_registry not_in [docker.io, gcr.io, registry.k8s.io, quay.io, ghcr.io]` |
| `CIS_4.3.2` | MEDIUM | `pod_spec_check` | `kubernetes.image_tag == "latest"` |
| `CIS_4.3.3` | MEDIUM | `pod_spec_check` | `container.image_pull_policy != "Always"` |
| `CIS_4.3.4` | MEDIUM | `pod_spec_check` | `container.image_scan_status != "scanned"` |
| `CIS_4.3.5` | HIGH | `pod_spec_check` | `container.image_registry_auth == false` |
| `CIS_4.3.6` | HIGH | `pod_spec_check` | `container.image_signed == false` |

### Resource Management (CIS 4.4.x) — 5 rules

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_4.4.1` | MEDIUM | `pod_spec_check` | `container.memory_limit == ""` |
| `CIS_4.4.2` | MEDIUM | `pod_spec_check` | `container.cpu_limit == ""` |
| `CIS_4.4.3` | MEDIUM | `pod_spec_check` | `container.memory_request == ""` |
| `CIS_4.4.4` | MEDIUM | `pod_spec_check` | `container.cpu_request == ""` |
| `CIS_4.4.5` | LOW | `pod_spec_check` | `container.storage_request == ""` |

### RBAC & Access Controls (CIS 5.x.x) — 9 rules

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_5.1.1` | CRITICAL | `pod_spec_check` | `kubernetes.rbac_enforced == false` |
| `CIS_5.1.2` | HIGH | `pod_spec_check` | `kubernetes.rbac_level > 2` |
| `CIS_5.2.1` | HIGH | `pod_spec_check` | `kubernetes.automount_service_account_token == true` ³ |
| `CIS_5.2.2` | MEDIUM | `pod_spec_check` | `kubernetes.service_account_token_age > 2592000` (30 days) |
| `CIS_5.3.1` | HIGH | `pod_spec_check` | `kubernetes.service_account == "default"` |
| `CIS_5.3.2` | HIGH | `pod_spec_check` | `kubernetes.service_account_permissions > 5` |
| `CIS_5.4.1` | HIGH | `pod_spec_check` | `kubernetes.rbac_policy_defined == false` |
| `CIS_5.4.2` | HIGH | `pod_spec_check` | `kubernetes.role_permission_count > 10` |
| `CIS_5.5.1` | HIGH | `pod_spec_check` | `kubernetes.audit_logging_enabled == false` |

³ Required the `kubernetes.automount_service_account_token` case to be added to `extractField` in `engine.go` (Apr 20, 2026) — it was missing, causing this rule to never fire.

### Advanced Security (CIS 4.7.x–4.9.x) — 9 rules

| ControlID | Severity | EventTypes | Key Condition |
|---|---|---|---|
| `CIS_4.7.1` | MEDIUM | `pod_spec_check` | `container.seccomp_profile == ""` |
| `CIS_4.7.2` | MEDIUM | `pod_spec_check` | `container.apparmor_profile == ""` |
| `CIS_4.7.3` | MEDIUM | `process_execution` | `container.selinux_level == "unrestricted"` |
| `CIS_4.8.1` | HIGH | `file_access` ¹ | `container.read_only_filesystem == false` |
| `CIS_4.8.2` | HIGH | `pod_spec_check` | `container.volume_type in [hostPath, emptyDir, local]` |
| `CIS_4.9.1` | HIGH | `pod_spec_check` | `container.runtime not_in [containerd, cri-o, crio]` ⁴ |
| `CIS_4.9.2` | HIGH | `process_execution` | `container.isolation_level < 1` ⁵ |
| `CIS_4.9.3` | MEDIUM | `process_execution` | `container.kernel_hardening == false` |

¹ Same `file_write` → `file_access` fix as CIS_4.5.5 (Feb 18, 2026).

⁴ **Runtime allowlist (Mar 29, 2026):** approved runtimes are `containerd`, `cri-o`, and `crio` (the CRI-O alias). Any other runtime prefix (e.g. `docker`, `unknown`) triggers a violation.

⁵ **Isolation threshold (Mar 29, 2026):** threshold is `< 1` (not `== 0`) — level 1+ is treated as baseline hardened to reduce noisy false positives. Level 0 means zero hardening signals detected.

---

## Key Anchor Comments

| Location | Anchor summary |
|---|---|
| `CIS_4.5.5` / `CIS_4.8.1` | Event type mismatch `file_write` → `file_access` fix — Feb 18, 2026 |
| `CIS_4.6.1` | `network_connection` added alongside `network_policy_check` — Feb 18, 2026 |
| `CIS_4.9.1` | Runtime allowlist clarification: approved runtime set — Mar 29, 2026 |
| `CIS_4.9.2` | Isolation threshold tuning: `< 1` to reduce false positives — Mar 29, 2026 |

---

## Related Files

| File | Relationship |
|---|---|
| [engine.go](./engine.md) | `loadCISRules()` returns `CISControls`; `extractField` maps field paths to these rules |
| [loader.go](./loader.md) | External sources that override `CISControls` when present |
| [pkg/enrichment/types.go](../enrichment/types.md) | All field paths in conditions resolve to fields on `EnrichedEvent` |
