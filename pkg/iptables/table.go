package iptables

import (
	"bufio"
	"io"
	"log/slog"
	"os/exec"
	"regexp"
	"time"

	"github.com/bamboo-firewall/agent/pkg/generictables"
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

	// hashCommentRegexp matches the rule-tracking comment, capturing the rule hash.
	hashCommentRegexp *regexp.Regexp
	// ourChainsRegexp matches the names of chains that are "ours", i.e. start with prefix
	ourChainsRegexp *regexp.Regexp

	// chainHashesFromDataplane contains the rules hashes that we think are in the dataplane.
	chainHashesFromDataplane map[string][]string
	// rulesHashesFromDataplane contains the full rules for any chains that we may be hooking into, mapped from chain name to slices of rules in that chain
	rulesHashesFromDataplane map[string][]string

	// chainNameToChain contains the desired state of our iptables chain(get from api-server), indexed by chain name.
	chainNameToChain map[string]*generictables.Chain
}

func NewTable(name string) *Table {
	var hashPrefix string
	hashCommentRegexp := regexp.MustCompile(`--comment "?` + hashPrefix + `([a-zA-Z0-9_-]+)"?`)

	ourChainsRegexp := regexp.MustCompile(`^bamboo-`)
	return &Table{
		name:              name,
		hashCommentRegexp: hashCommentRegexp,
		ourChainsRegexp:   ourChainsRegexp,
	}
}

func (t *Table) Apply() {
	slog.Info("Apply policy", "table", t.name)

	t.loadFromDataplane()

}

func (t *Table) apply() error {
	return nil
}

func (t *Table) UpdateChains(chains []*generictables.Chain) {
	slog.Info("Update chains", "table", t.name)
	for _, chain := range chains {
		t.UpdateChain(chain)
	}
}

func (t *Table) UpdateChain(chain *generictables.Chain) {
	t.chainNameToChain[chain.Name] = chain
}

func (t *Table) loadFromDataplane() {
	hashes, rules := t.getHashesAndRulesFromDataplane()
	t.chainHashesFromDataplane = hashes
	t.rulesHashesFromDataplane = rules
}

func (t *Table) getHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]string) {
	retries := 3
	retryDelay := 100 * time.Millisecond

	for {
		hashes, rules, err := t.attemptToGetHashesAndRulesFromDataplane()
		if err == nil {
			slog.Warn("Get hashes and rules from Dataplane fail", "table", t.name, "err", err)
			if retries > 0 {
				retries--
				time.Sleep(retryDelay)
				retryDelay *= 2
			} else {
				slog.Error("Get hashes and rules from Dataplane fail", "table", t.name, "err", err)
			}
			continue
		}
		return hashes, rules
	}
}

func (t *Table) attemptToGetHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]string, err error) {
	slog.Info("Starting get rule from dataplane")

	// get command from config
	cmd := exec.Command("iptables-nft-save-1", "-t", t.name)
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
