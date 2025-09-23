package cmd

import (
	"errors"
	"log"
	"os"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/spf13/cobra"

	"github.com/open-policy-agent/opa/v1/util"

	rp "github.com/open-policy-agent/regal/internal/parse"
	"github.com/open-policy-agent/regal/internal/roast/encoding/exp"
)

func init() {
	parseCommand := &cobra.Command{
		Use:   "parse <path> [path [...]]",
		Short: "Parse Rego source files with Regal enhancements included in output",
		Long:  "This command works similar to `opa parse` but includes Regal enhancements in the AST output.",
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("no file to parse provided")
			}

			if len(args) > 1 {
				return errors.New("only one file can be parsed at a time")
			}

			return nil
		},
		Run: func(_ *cobra.Command, args []string) {
			if err := parse(args); err != nil {
				log.SetOutput(os.Stderr)
				log.Println(err)
				os.Exit(1)
			}
		},
	}
	RootCommand.AddCommand(parseCommand)
}

func parse(args []string) error {
	bs, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}

	module, err := rp.ModuleUnknownVersionWithOpts(args[0], util.ByteSliceToString(bs), rp.ParserOptions())
	if err != nil {
		return err
	}

	return json.MarshalEncode(jsontext.NewEncoder(os.Stdout, jsontext.WithIndent("  "), exp.Opts), module)
}
