package iptables

import (
	"bufio"
	"io"
	"log/slog"
	"os/exec"
	"regexp"

	"github.com/bamboo-firewall/agent/generictables"
)

var (
	chainRegexp      = regexp.MustCompile(`^:(\S+)`)
	ruleAppendRegexp = regexp.MustCompile(`^-A (\S+)`)
)

type Table struct {
	name                 string
	renderer             Renderer
	chainToInsertedRules map[string][]generictables.Rule
	chainToAppendedRules map[string][]generictables.Rule

	hashCommentRegexp *regexp.Regexp

	chainNameToChain map[string]*generictables.Chain
}

func NewTable(name string) *Table {
	var hashPrefix string
	hashCommentRegexp := regexp.MustCompile(`--comment "?` + hashPrefix + `([a-zA-Z0-9_-]+)"?`)
	return &Table{
		name:              name,
		hashCommentRegexp: hashCommentRegexp,
	}
}

func (t *Table) Apply() {
	t.getChainFromDataplane()
}

func (t *Table) getChainFromDataplane() (hashes map[string][]string, rules map[string][]string, err error) {
	slog.Info("Starting get rule from dataplane")

	// get command from config
	cmd := exec.Command("iptables-nft-save", "-t", t.name)
	slog.Info("command", "command", cmd.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slog.Error("Error getting rule from dataplane stdout", "err", err)
		return
	}
	if err = cmd.Start(); err != nil {
		slog.Error("Error getting rule from dataplane start", "err", err)
		return
	}
	hashes, rules, err = t.readHashesAndRulesFrom(stdout)
	if err != nil {
		slog.Error("Error getting rule from dataplane scanner", "err", err)
		return
	}
	if err = cmd.Wait(); err != nil {
		slog.Error("Error getting rule from dataplane waiting", "err", err)
	}
	slog.Info("Finished getting rule from dataplane", "hashes", hashes, "rules", rules)
	return
}

func (t *Table) readHashesAndRulesFrom(r io.ReadCloser) (hashes map[string][]string, rules map[string][]string, err error) {
	hashes = make(map[string][]string)
	rules = make(map[string][]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()

		slog.Info("iptables", "line", string(line))

		captures := chainRegexp.FindSubmatch(line)
		if captures != nil {
			chainName := string(captures[1])
			hashes[chainName] = []string{}
			continue
		}

		captures = ruleAppendRegexp.FindSubmatch(line)
		if captures == nil {
			slog.Error("Error parsing rule", "line", string(line))
			continue
		}
		chainName := string(captures[1])

		hash := ""
		captures = t.hashCommentRegexp.FindSubmatch(line)
		if captures != nil {
			hash = string(captures[1])
		} else {
			hash = "OLD INSERT RULE"
		}
		hashes[chainName] = append(hashes[chainName], hash)
	}
	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}
	return hashes, rules, nil
}
