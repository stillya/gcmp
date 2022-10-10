package cmd

// CommandExecutor extends flags.Commander
// All command must implement this interface
type CommandExecutor interface {
	Execute(args []string) error
}
