package cli

// Root returns the command tree. `describe` derives the machine-readable
// manifest from this same tree, so docs never drift from behaviour.
func Root() *Command {
	return &Command{
		Name:    "syssec",
		Summary: "agent-native host security posture, vulnerability intel and history",
		Sub: []*Command{
			statusCmd(),
			scanCmd(),
			reportCmd(),
			vulnsCmd(),
			historyCmd(),
			diffCmd(),
			explainCmd(),
			checksCmd(),
			inventoryCmd(),
			waiveCmd(),
			{Name: "intel", Summary: "vulnerability intelligence (OSV + CISA KEV + EPSS)", Sub: []*Command{intelSyncCmd()}},
			pruneCmd(),
			describeCmd(),
			versionCmd(),
		},
	}
}
