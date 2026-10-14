package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noaadapter"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa is the "model-driven context compaction" mechanism introduced in norma
// v0.4.0, an experimental platform feature the user toggles in system settings.
// It is mutually exclusive with the built-in compaction: noaadapter.Enable is the
// sole entry point, hooking up the context takeover (Compactor), the Compress tool
// and three resident prompts in one go; not calling Enable means it is off (the
// built-in compaction works as usual). The toggle is resolved by the noaEnabledFn
// each agent injects, read once per run, so flipping it only affects runs started
// afterward and needs no agent rebuild.

// enableNoa wires noa into opts when the resolver reports it on. archiveRoot is the
// persistence base directory for compacted source text (taken from the global
// workDir, so every agent consolidates under <workDir>/noa rather than scattering
// across task/intent directories); sessionID names the archive subdirectory beneath
// it (globally unique, so no collisions within the same base directory).
//
// noa is experimental: a failed hookup must not interrupt a real task. On error it
// reports via onWarn and falls back to the built-in compaction. On successful enable
// it clears opts.Compaction to avoid agentcore warning about "two context managers
// set at once".
func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("noa compaction failed to enable; falling back to built-in compaction: " + err.Error())
		}
		return
	}
	// The Compactor overrides Compaction, but with both set agentcore warns every time; clear it explicitly.
	opts.Compaction = nil
}
