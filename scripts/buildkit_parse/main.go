// Prints BuildKit's own parse of a Dockerfile (read from stdin) as JSON, so
// that VulnScan's hand-written parser can be checked against it
// (scripts/check_dockerfile_parser.py). A development tool only: VulnScan
// itself does not use it.
package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type instruction struct {
	Keyword   string   `json:"keyword"`
	Original  string   `json:"original"`
	Start     int      `json:"start"`
	End       int      `json:"end"`
	Flags     []string `json:"flags"`
	JSON      bool     `json:"json"`
	Args      []string `json:"args"`
	Heredocs  []string `json:"heredocs"`
}

func main() {
	result, err := parser.Parse(os.Stdin)
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
		return
	}
	out := []instruction{}
	for _, node := range result.AST.Children {
		args := []string{}
		for n := node.Next; n != nil; n = n.Next {
			args = append(args, n.Value)
		}
		heredocs := []string{}
		for _, h := range node.Heredocs {
			heredocs = append(heredocs, h.Name+"\x00"+h.Content)
		}
		flags := node.Flags
		if flags == nil {
			flags = []string{}
		}
		out = append(out, instruction{
			Keyword:  strings.ToUpper(node.Value),
			Original: node.Original,
			Start:    node.StartLine,
			End:      node.EndLine,
			Flags:    flags,
			JSON:     node.Attributes["json"],
			Args:     args,
			Heredocs: heredocs,
		})
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"instructions": out,
		"escape":       string(result.EscapeToken),
	})
}
