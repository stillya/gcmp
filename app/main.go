package main

import (
	"gcmp/app/cmd"
	log "github.com/go-pkgz/lgr"
	"github.com/jessevdk/go-flags"
	"os"
)

// Opts with all cli commands
type Opts struct {
	Server cmd.ServerCommand `command:"server"`
	Client cmd.ClientCommand `command:"client"`
}

func main() {
	log.Setup(log.Msec, log.LevelBraces)

	var opts Opts
	parser := flags.NewParser(&opts, flags.Default)

	parser.CommandHandler = func(command flags.Commander, args []string) error {
		c := command.(cmd.CommandExecutor)
		err := c.Execute(args)
		if err != nil {
			log.Printf("[ERROR] failed with %+v", err)
		}
		return err
	}

	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}
}
