# `pkg/ebpf/bytecode_embed.go` — eBPF Bytecode Embedding

**Package:** `ebpf`
**Path:** `pkg/ebpf/bytecode_embed.go`
**Lines:** ~30
**Added:** Dec 27, 2025

---

## Overview

Uses `//go:embed` to bundle compiled eBPF ELF object files (`*.o`) directly into the Go binary. This eliminates any runtime filesystem dependency on external `.o` files — the agent is fully self-contained.

---

## Embed Directive

```go
//go:embed programs/bin/*
var programFiles embed.FS
```

The pattern `programs/bin/*` embeds every file in that directory. A `.gitkeep` file ensures the directory exists in the repository even when the `.o` files are not yet compiled, so `go build` doesn't fail with a missing embed path (Bug fix Mar 29, 2026).

---

## Functions

### `GetProgram(name string) ([]byte, error)`

Returns the compiled ELF bytecode for the named program.

- Path resolved as: `programs/bin/<name>.o`
- Returns an actionable error message if the file is missing: `"run make -C pkg/ebpf/programs all"`
- Used by `loadProgramSet()` in `loader.go` before every program load

### `ListPrograms`

```go
var ListPrograms = []string{
    "process", "network", "file", "capability", "dns", "tls",
}
```

Exported slice of all program names. Used for verification and debugging.

---

## Build Dependency

The `.o` files in `programs/bin/` are compiled from C sources by `make -C pkg/ebpf/programs all`. They are not committed to the repository. The build process must compile them before `go build` can embed them.

---

## Key Anchor Comment

| Lines | Anchor summary |
|---|---|
| 282–284 | `programs/bin/*` embed pattern — `.gitkeep` fallback prevents build failure without precompiled `.o` |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/loader.go](./loader.md) | Calls `GetProgram()` in `loadProgramSet()` |
| `pkg/ebpf/programs/` | C source files and Makefile that produce the `.o` binaries |
