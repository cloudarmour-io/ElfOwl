// ANCHOR: Cilium/eBPF Program Loader - Dec 27, 2025
// Loads compiled eBPF bytecode and manages program lifecycle
// Provides abstraction over cilium/ebpf Collection API for monitor integration

package ebpf

import (
	"embed"
	"fmt"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// ============================================================================
// Reader Interface - Abstracts event stream source
// ============================================================================

// Reader defines the interface for reading eBPF events from kernel
// Implementations: PerfReader (perf buffers), RingBufferReader (ring buffers)
type Reader interface {
	// Read returns the next event or error
	Read() ([]byte, error)

	// Close releases reader resources
	Close() error
}

// ============================================================================
// ProgramSet - Wraps individual eBPF program + maps + reader
// ============================================================================

// ProgramSet represents a compiled eBPF program and its associated resources
// Example: ProcessMonitor consists of one program with process_events perf buffer
type ProgramSet struct {
	// Program is the loaded eBPF program (e.g., sched_process_exec tracepoint)
	Program *ebpf.Program

	// Maps contains all maps used by this program (perf buffers, ring buffers, etc.)
	Maps map[string]*ebpf.Map

	// Reader provides access to event stream from kernel
	// nil if program doesn't produce events (e.g., helper-only programs)
	Reader Reader

	// Logger for diagnostics
	Logger *zap.Logger
}

// ============================================================================
// Collection - Wraps all loaded eBPF programs
// ============================================================================

// Collection represents all loaded eBPF programs for elf-owl
// One entry per monitoring domain (process, network, file, capability, dns)
type Collection struct {
	// Process monitors process execution (exec syscalls)
	Process *ProgramSet

	// Network monitors socket connections (TCP/UDP)
	Network *ProgramSet

	// File monitors file operations (open, write, chmod)
	File *ProgramSet

	// Capability monitors Linux capability usage
	Capability *ProgramSet

	// DNS monitors DNS queries and responses
	DNS *ProgramSet

	// Logger for diagnostics
	Logger *zap.Logger

	// bytecode holds embedded compiled eBPF programs
	bytecode map[string][]byte
}

// ============================================================================
// LoadPrograms - Main entry point for loading eBPF programs
// ============================================================================

// LoadPrograms loads all compiled eBPF programs from embedded bytecode
// Returns Collection ready for use by agent monitors
//
// Flow:
// 1. Extract embedded .o bytecode files via GetProgram()
// 2. Parse ELF bytecode via cilium/ebpf.LoadCollectionSpec()
// 3. Load programs into kernel
// 4. Wrap in ProgramSet with Reader for event streaming
// 5. Return Collection for agent to use
func LoadPrograms(logger *zap.Logger) (*Collection, error) {
	// ANCHOR: Load all eBPF programs from bytecode - Dec 27, 2025
	// Loads compiled ELF bytecode for all 5 monitors into kernel

	coll := &Collection{
		Logger:   logger,
		bytecode: make(map[string][]byte),
	}

	// Load bytecode for each program from embedded files
	logger.Info("loading eBPF programs from embedded bytecode")

	// ANCHOR: Load all eBPF programs - Dec 27, 2025
	// Verifies all bytecode files are available and can be parsed
	// Actual kernel loading requires CAP_BPF, CAP_PERFMON, and valid kernel eBPF support

	programs := map[string]string{
		ProcessProgramName:    "process execution",
		NetworkProgramName:    "network connections",
		FileProgramName:       "file access",
		CapabilityProgramName: "Linux capabilities",
		DNSProgramName:        "DNS queries",
	}

	loadedCount := 0
	for progName, progDesc := range programs {
		data, err := GetProgram(progName)
		if err != nil {
			logger.Warn("program bytecode not available",
				zap.String("program", progName),
				zap.String("description", progDesc),
				zap.Error(err))
			continue
		}

		// Verify bytecode is valid ELF format
		if len(data) < 64 {
			logger.Warn("bytecode too small for valid ELF",
				zap.String("program", progName),
				zap.Int("size", len(data)))
			continue
		}

		// Check ELF magic number
		if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
			logger.Warn("invalid ELF magic in bytecode",
				zap.String("program", progName))
			continue
		}

		// Log successful bytecode verification
		logger.Info("program bytecode verified",
			zap.String("program", progName),
			zap.String("description", progDesc),
			zap.Int("bytecodeSize", len(data)))

		loadedCount++

		// TODO (Phase 3): Actually load into kernel
		// Requires:
		// 1. Write bytecode to temp file (LoadCollectionSpec takes file path)
		// 2. Parse with ebpf.LoadCollectionSpec(tmpFile)
		// 3. Load programs via spec.LoadAndAssign()
		// 4. Attach programs to kernel tracepoints
		// 5. Create ProgramSet with event readers
		//
		// For now, we verify bytecode availability and format
	}

	logger.Info("eBPF program loading verification complete",
		zap.Int("loaded", loadedCount),
		zap.Int("total", len(programs)),
		zap.String("note", "Phase 3 will implement actual kernel loading"))

	return coll, nil
}

// ============================================================================
// Close - Cleanup resources
// ============================================================================

// Close gracefully closes all eBPF programs and readers
// Called during agent shutdown
func (c *Collection) Close() error {
	if c == nil {
		return nil
	}

	var errs []error

	// Close all program sets in order
	if c.Process != nil {
		if err := c.Process.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close process program: %w", err))
		}
	}

	if c.Network != nil {
		if err := c.Network.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close network program: %w", err))
		}
	}

	if c.File != nil {
		if err := c.File.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close file program: %w", err))
		}
	}

	if c.Capability != nil {
		if err := c.Capability.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close capability program: %w", err))
		}
	}

	if c.DNS != nil {
		if err := c.DNS.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close dns program: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	return nil
}

// ============================================================================
// ProgramSet Methods
// ============================================================================

// Close closes the program set and all its resources
func (ps *ProgramSet) Close() error {
	if ps == nil {
		return nil
	}

	var errs []error

	// Close reader first (may be actively reading)
	if ps.Reader != nil {
		if err := ps.Reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close reader: %w", err))
		}
	}

	// Close all maps
	for name, m := range ps.Maps {
		if m != nil {
			if err := m.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close map %s: %w", name, err))
			}
		}
	}

	// Close program
	if ps.Program != nil {
		if err := ps.Program.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close program: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("program set close errors: %v", errs)
	}

	return nil
}

// ============================================================================
// Helper Functions (Phase 2 Implementation)
// ============================================================================

// loadBytecode extracts embedded eBPF bytecode from compiled binaries
// Phase 2: Uses //go:embed to include .o files
func loadBytecode(progFiles embed.FS) (map[string][]byte, error) {
	// TODO (Phase 2): Implement bytecode loading
	// Walk programs/bin/*.o and load each file
	bytecode := make(map[string][]byte)

	// Phase 2 pseudocode:
	// fs.WalkDir(progFiles, "programs/bin", func(path string, d fs.DirEntry) error {
	//     if !strings.HasSuffix(path, ".o") {
	//         return nil
	//     }
	//     data, err := fs.ReadFile(progFiles, path)
	//     bytecode[filepath.Base(path)] = data
	//     return err
	// })

	return bytecode, nil
}

// newProgramSet creates a ProgramSet from loaded bytecode
// Phase 2: Parses ELF sections and attaches tracepoints
func newProgramSet(name string, bytecode []byte, logger *zap.Logger) (*ProgramSet, error) {
	// TODO (Phase 2): Implement program loading
	// 1. Parse ELF bytecode via cilium/ebpf spec
	// 2. Create ebpf.Program via CollectionSpec.Progs
	// 3. Load into kernel
	// 4. Create Reader (PerfBufferReader or RingBufferReader)
	// 5. Return ProgramSet

	return nil, fmt.Errorf("Phase 2 implementation: load %s program", name)
}

// attachTracepoint attaches eBPF program to kernel tracepoint
// Phase 2: Calls perf_event_open for tp_btf or raw_tracepoint
func attachTracepoint(prog *ebpf.Program, group, name string) error {
	// TODO (Phase 2): Implement tracepoint attachment
	// Use golang.org/x/sys/unix for perf_event_open syscall
	// Steps:
	// 1. Find tracepoint ID from /sys/kernel/debug/tracing/events/{group}/{name}/id
	// 2. Call perf_event_open with PERF_TYPE_TRACEPOINT
	// 3. Attach program via BPF_LINK_CREATE

	return fmt.Errorf("Phase 2 implementation: attach %s:%s", group, name)
}

// ============================================================================
// Event Reading (Phase 2 Implementation)
// ============================================================================

// ============================================================================
// Event Reader Implementations
// ============================================================================

// PerfBufferReader reads events from a perf buffer map
// Implements Reader interface for perf_event_array maps
// ANCHOR: Perf Buffer Reader - Phase 2: Monitor Implementation - Dec 27, 2025
// Reads events from per-CPU perf buffers (available on all eBPF kernels)
type PerfBufferReader struct {
	// TODO (Phase 3): Integrate cilium/ebpf perf.Reader
	// perf.Reader handles multi-CPU perf event arrays
	// Each CPU has page-backed mmap'd buffer
	closed bool
}

// Read returns next event from perf buffer
func (pr *PerfBufferReader) Read() ([]byte, error) {
	if pr.closed {
		return nil, fmt.Errorf("reader closed")
	}

	// TODO (Phase 3): Implement actual perf buffer reading
	// Will use cilium/ebpf perf.Reader to aggregate events from all CPUs
	// Blocks until event available or timeout (5 seconds)
	// Returns raw event bytes for parsing by monitor

	return nil, fmt.Errorf("Phase 3 implementation: perf buffer event streaming")
}

// Close closes the perf buffer reader
func (pr *PerfBufferReader) Close() error {
	pr.closed = true
	// TODO (Phase 3): Close perf.Reader and unmap buffers
	return nil
}

// RingBufferReader reads events from a ring buffer map
// Implements Reader interface for ringbuf maps (kernel 5.8+)
// ANCHOR: Ring Buffer Reader - Phase 2: Monitor Implementation - Dec 27, 2025
// Reads events from single shared ring buffer (preferred for modern kernels)
type RingBufferReader struct {
	// TODO (Phase 3): Integrate cilium/ebpf ringbuf.Reader
	// ringbuf.Reader handles single shared ring buffer
	// More efficient than perf buffers
	closed bool
}

// Read returns next event from ring buffer
func (rr *RingBufferReader) Read() ([]byte, error) {
	if rr.closed {
		return nil, fmt.Errorf("reader closed")
	}

	// TODO (Phase 3): Implement actual ring buffer reading
	// Will use cilium/ebpf ringbuf.Reader to read events
	// Blocks until event available or timeout (5 seconds)
	// Returns raw event bytes for parsing by monitor

	return nil, fmt.Errorf("Phase 3 implementation: ring buffer event streaming")
}

// Close closes the ring buffer reader
func (rr *RingBufferReader) Close() error {
	rr.closed = true
	// TODO (Phase 3): Close ringbuf.Reader
	return nil
}
