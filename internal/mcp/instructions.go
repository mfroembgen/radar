package mcp

import (
	"sync/atomic"

	"github.com/skyhook-io/radar/pkg/investigation"
)

// instructionsDisabled drops the server instructions of the public servers for
// a client that connects several Radar instances and needs the guidance from
// only one of them.
var instructionsDisabled atomic.Bool

// SetInstructionsDisabled turns the server instructions off or on for servers
// built afterwards. Call it before NewHandler.
func SetInstructionsDisabled(disabled bool) { instructionsDisabled.Store(disabled) }

// serverInstructions is the text a server registering the given tool set sends
// when a client connects, in the initialize result or, on protocol 2026-07-28,
// the server/discover result: Radar's general guidance
// (pkg/investigation/guidance.go), with the write-tool routing only where the
// write tools are registered. --mcp-no-instructions sends none.
func serverInstructions(includeWrites bool) string {
	if instructionsDisabled.Load() {
		return ""
	}
	if includeWrites && execToolsEnabled.Load() {
		return investigation.GeneralGuidanceExec
	}
	return investigation.GeneralGuidance(includeWrites)
}
