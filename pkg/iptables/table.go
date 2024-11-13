package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bamboo-firewall/agent/pkg/generictables"
)

const (
	modeLegacy = "legacy"
	modeNFT    = "nft"

	defaultLockSecondTimeout = 3

	maxNameLength = 28
)

var (
	chainRegexp      = regexp.MustCompile(`^:(\S+)`)
	ruleAppendRegexp = regexp.MustCompile(`^-A (\S+)`)
)

type Table struct {
	name              string
	ipVersion         int
	version           version
	hasWait           bool
	waitSupportSecond bool
	lockSecondTimeout int
	mode              string
	renderer          Renderer

	// hashCommentRegexp matches the rule-tracking comment, capturing the rule hash.
	hashCommentRegexp *regexp.Regexp
	// ourChainsRegexp matches the names of chains that are "ours", i.e. start with prefix
	ourChainsRegexp *regexp.Regexp

	// chainHashesFromDataplane contains the rules hashes that we think are in the dataplane.
	chainHashesFromDataplane map[string][]string
	// rawRulesOfDefaultChainFromDataplane contains the full rules of default chain that has our rules
	rawRulesOfDefaultChainFromDataplane map[string][]string

	// chainNameToChain contains the desired state of our iptables chain(get from api-server), indexed by chain name.
	chainNameToChain map[string]*generictables.Chain

	// defaultOurRuleOfDefaultChain contain our rule in default chain
	defaultOurRuleOfDefaultChain map[string]generictables.Rule

	// needCleanToDataplane clean all our rules and chains
	needCleanToDataplane bool
	// inSyncWithDataplane get policy from dataplane done
	inSyncWithDataplane bool

	restoreCmd string
	saveCmd    string
}

func NewTable(name string, hashPrefix string, opts ...option) (*Table, error) {
	if name == "" {
		return nil, fmt.Errorf("table name is empty")
	}
	if hashPrefix == "" {
		return nil, fmt.Errorf("hash prefix is empty")
	}

	t := &Table{
		name:                         name,
		renderer:                     NewRenderer(hashPrefix),
		chainNameToChain:             make(map[string]*generictables.Chain),
		defaultOurRuleOfDefaultChain: make(map[string]generictables.Rule),
	}
	for _, opt := range opts {
		opt(t)
	}

	ipTableVersion, mode, err := getIptablesVersion(t.ipVersion)
	if err != nil {
		return nil, err
	}
	t.mode = mode
	t.version = ipTableVersion
	if ipTableVersion.isGTE(v1dot4dot20) {
		t.hasWait = true
	}
	if ipTableVersion.isGTE(v1dot6dot0) {
		t.waitSupportSecond = true
	}

	t.hashCommentRegexp = regexp.MustCompile(`--comment "?` + hashPrefix + `([a-zA-Z0-9_-]+)"?`)

	ourChainPrefix := []string{"BAMBOO-"}
	ourChainPattern := "^(" + strings.Join(ourChainPrefix, "|") + ")"
	t.ourChainsRegexp = regexp.MustCompile(ourChainPattern)

	restoreCmd, err := getIptablesRestoreOrSaveCmd(mode, t.ipVersion, "restore")
	if err != nil {
		return nil, err
	}
	t.restoreCmd = restoreCmd

	saveCmd, err := getIptablesRestoreOrSaveCmd(mode, t.ipVersion, "save")
	if err != nil {
		return nil, err
	}
	t.saveCmd = saveCmd

	slog.Debug("iptables info", "version", t.version, "ipVersion", t.ipVersion,
		"restore cmd", t.restoreCmd, "save cmd", saveCmd)

	return t, nil
}

func getIptablesRestoreOrSaveCmd(mode string, ipVersion int, restoreOrSave string) (string, error) {
	verInFix := ""
	if ipVersion == generictables.IPFamily6 {
		verInFix = "6"
	}
	candidates := []string{
		"ip" + verInFix + "tables-" + mode + "-" + restoreOrSave,
		"ip" + verInFix + "tables-" + restoreOrSave,
	}
	for _, candidate := range candidates {
		_, err := exec.LookPath(candidate)
		if err == nil {
			return candidate, nil
		} else {
			slog.Warn("look path of command failed", "command", candidate, "err", err)
		}
	}
	return "", fmt.Errorf("no iptables restore command found for mode %s and ipVersion %d", mode, ipVersion)
}

func (t *Table) SetDefaultRuleOfDefaultChain(chainName string, rule generictables.Rule) {
	t.defaultOurRuleOfDefaultChain[chainName] = rule
}

// UpdateChains update rules of our chain
func (t *Table) UpdateChains(chains []*generictables.Chain) {
	t.chainNameToChain = make(map[string]*generictables.Chain)
	for _, chain := range chains {
		t.UpdateChain(chain)
	}
}

func (t *Table) UpdateChain(chain *generictables.Chain) {
	t.chainNameToChain[chain.Name] = chain
}

func (t *Table) NeedClean() {
	t.needCleanToDataplane = true
}

func (t *Table) Apply() {
	if !t.inSyncWithDataplane {
		t.loadFromDataplane()
	}
	retries := 3
	retryDelay := 100 * time.Millisecond

	for {
		err := t.apply()
		if err != nil {
			slog.Warn("apply rule failed. Retrying", "table", t.name, "err", err)
			if retries > 0 {
				retries--
				time.Sleep(retryDelay)
				retryDelay *= 2
			} else {
				slog.Error("apply rule fail after retry.", "table", t.name, "err", err)
				break
			}
			continue
		}
		break
	}
	t.inSyncWithDataplane = false
	t.needCleanToDataplane = false
}

func (t *Table) apply() error {
	slog.Debug("start apply policy", "chainNameToChain", t.chainNameToChain, "chainHashesFromDataplane",
		t.chainHashesFromDataplane, "ipVersion", t.ipVersion)
	defer slog.Debug("finish apply policy", "ipVersion", t.ipVersion)
	if t.needCleanToDataplane {
		return t.Clean()
	}

	if len(t.chainNameToChain) == 0 {
		return nil
	}

	buf := new(RestoreBuilder)
	buf.StartTransaction(t.name)

	updatedChains := make(map[string]struct{})
	referenceChains := make(map[string]struct{})

	// iptables-nft-restore <v1.8.3 has a bug (https://bugzilla.netfilter.org/show_bug.cgi?id=1348)
	// where only the first replace command sets the rule index.  Work around that by refreshing the
	// whole chain using a flush.
	isIptablesCMDBug := false
	if t.mode == modeNFT && !t.version.isGTE(v1dot8dot3) {
		isIptablesCMDBug = true
	}

	// First: write chain
	for chainName, chain := range t.chainNameToChain {
		currentHashes := t.renderer.RuleHashes(chain)
		previousHashes := t.chainHashesFromDataplane[chainName]
		referenceChains[chainName] = struct{}{}

		if reflect.DeepEqual(previousHashes, currentHashes) {
			updatedChains[chainName] = struct{}{}
			continue
		}

		chainNeedToBeFlushed := false
		if isIptablesCMDBug {
			// flush all. Create new chain
			chainNeedToBeFlushed = true
		} else if len(previousHashes) == 0 {
			// chain not exist in dataplane. Create new chain
			chainNeedToBeFlushed = true
		}

		if chainNeedToBeFlushed {
			buf.WriteChain(chainName)
		}
	}

	// Second: write rule
	// Step 1: Write our rule to our chain(user-defined policy)
	for chainName, chain := range t.chainNameToChain {
		if _, ok := updatedChains[chainName]; ok {
			continue
		}
		if chainName == generictables.OurDefaultInputChain || chainName == generictables.OurDefaultOutputChain {
			continue
		}

		var previousHashes []string
		if !isIptablesCMDBug {
			previousHashes = t.chainHashesFromDataplane[chainName]
		}
		currentHashes := t.renderer.RuleHashes(chain)
		for i := 0; i < len(currentHashes) || i < len(previousHashes); i++ {
			var line string
			if i < len(currentHashes) && i < len(previousHashes) {
				if currentHashes[i] == previousHashes[i] {
					continue
				}
				line = t.renderer.RenderReplace(&chain.Rules[i], chainName, i+1, currentHashes[i])
			} else if i < len(previousHashes) {
				// previousHashed was longer, remove the old rules from the end
				line = t.renderer.RenderDeleteAtIndex(chainName, len(currentHashes)+1)
			} else {
				line = t.renderer.RenderAppend(&chain.Rules[i], chainName, currentHashes[i])
			}
			buf.WriteRule(line)
		}
	}
	// Step 2: Write our rule to our default chain
	for chainName, chain := range t.chainNameToChain {
		if _, ok := updatedChains[chainName]; ok {
			continue
		}
		if !(chainName == generictables.OurDefaultInputChain || chainName == generictables.OurDefaultOutputChain) {
			continue
		}

		var previousHashes []string
		if !isIptablesCMDBug {
			previousHashes = t.chainHashesFromDataplane[chainName]
		}
		currentHashes := t.renderer.RuleHashes(chain)
		for i := 0; i < len(currentHashes) || i < len(previousHashes); i++ {
			var line string
			if i < len(currentHashes) && i < len(previousHashes) {
				if currentHashes[i] == previousHashes[i] {
					continue
				}
				line = t.renderer.RenderReplace(&chain.Rules[i], chainName, i+1, currentHashes[i])
			} else if i < len(previousHashes) {
				// previousHashed was longer, remove the old rules from the end
				line = t.renderer.RenderDeleteAtIndex(chainName, i+1)
			} else {
				line = t.renderer.RenderAppend(&chain.Rules[i], chainName, currentHashes[i])
			}
			buf.WriteRule(line)
		}

	}
	// Step 3: Write our rule of default chain
	// Make sure one our rule of last of default chain
	for chainName, defaultRule := range t.defaultOurRuleOfDefaultChain {
		defaultHashes := t.renderer.RuleHashes(&generictables.Chain{
			Name:  chainName,
			Rules: []generictables.Rule{defaultRule},
		})
		defaultHash := defaultHashes[0]
		if _, ok := t.chainHashesFromDataplane[chainName]; !ok {
			buf.WriteRule(t.renderer.RenderAppend(&defaultRule, chainName, defaultHash))
			continue
		}

		hashes := t.chainHashesFromDataplane[chainName]
		for i, hash := range hashes {
			if i == len(hashes)-1 {
				if hash == defaultHash {
					continue
				} else if hash != "" && hash != defaultHash {
					buf.WriteRule(t.renderer.RenderDelete(t.rawRulesOfDefaultChainFromDataplane[chainName][i]))
				}
				buf.WriteRule(t.renderer.RenderAppend(&defaultRule, chainName, defaultHash))
			} else {
				if hash != "" {
					buf.WriteRule(t.renderer.RenderDelete(t.rawRulesOfDefaultChainFromDataplane[chainName][i]))
				}
			}
		}
	}
	// Step 4: Delete all our unreferenced chain
	for chainName := range t.chainHashesFromDataplane {
		if _, ok := referenceChains[chainName]; ok {
			continue
		}
		if _, ok := t.defaultOurRuleOfDefaultChain[chainName]; ok {
			continue
		}
		buf.WriteChain(chainName)
		buf.WriteRule(fmt.Sprintf("--delete-chain %s", chainName))
	}

	buf.EndTransaction()
	if buf.IsEmpty() {
		slog.Info("No new rules applied", "ipVersion", t.ipVersion)
	} else {
		return t.execRestore(buf)
	}

	return nil
}

// Clean all our rules and chains
func (t *Table) Clean() error {
	slog.Debug("start clean policy", "chainHashesFromDataplane", t.chainHashesFromDataplane, "ipVersion", t.ipVersion)
	defer slog.Debug("finish clean policy", "ipVersion", t.ipVersion)
	buf := new(RestoreBuilder)
	buf.StartTransaction(t.name)

	// first: remove all our rule in default chain
	for chainName := range t.defaultOurRuleOfDefaultChain {
		hashes := t.chainHashesFromDataplane[chainName]
		for i, hash := range hashes {
			if hash != "" {
				buf.WriteRule(t.renderer.RenderDelete(t.rawRulesOfDefaultChainFromDataplane[chainName][i]))
			}
		}
	}

	// second: delete default our chain
	for chainName := range t.chainHashesFromDataplane {
		if !(chainName == generictables.OurDefaultInputChain || chainName == generictables.OurDefaultOutputChain) {
			continue
		}

		buf.WriteChain(chainName)
		buf.WriteRule(fmt.Sprintf("--delete-chain %s", chainName))
	}

	// third: delete all our chains
	for chainName := range t.chainHashesFromDataplane {
		if chainName == generictables.OurDefaultInputChain || chainName == generictables.OurDefaultOutputChain {
			continue
		}

		buf.WriteChain(chainName)
		buf.WriteRule(fmt.Sprintf("--delete-chain %s", chainName))
	}

	buf.EndTransaction()
	if buf.IsEmpty() {
		slog.Info("No rule to clean", "table", t.name)
	} else {
		return t.execRestore(buf)
	}

	return nil
}

func (t *Table) execRestore(buf *RestoreBuilder) error {
	slog.Debug("start exec restore", "ipVersion", t.ipVersion)
	defer slog.Debug("finish exec restore", "ipVersion", t.ipVersion)
	contentBytes := buf.buf.Next(buf.buf.Len())
	args := []string{"--noflush", "--verbose"}
	if t.hasWait {
		args = append(args, "--wait")
		if t.lockSecondTimeout != 0 && t.waitSupportSecond {
			args = append(args, strconv.Itoa(t.lockSecondTimeout))
		}
	} else {
		fmu, err := newXtablesFileLock()
		if err != nil {
			return fmt.Errorf("new xtables file lock failed. %v", err)
		}
		ul, err := fmu.tryLock()
		if err != nil {
			syscall.Close(fmu.fd)
			return fmt.Errorf("try xtables file lock failed. %v", err)
		}
		defer func() {
			_ = ul.Unlock()
		}()
	}

	var outputBuf, errBuf bytes.Buffer
	cmd := exec.Command(t.restoreCmd, args...)
	slog.Debug("exec restore", "cmd", cmd.String(), "content", string(contentBytes), "ipVersion", t.ipVersion)
	cmd.Stdin = bytes.NewReader(contentBytes)
	cmd.Stdout = &outputBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		slog.Error("restore fail", "cmd", cmd.String(), "input", string(contentBytes), "stdout", outputBuf.String(), "stderr", errBuf.String())
		return fmt.Errorf("restore failed. stderr: %s . err: %w", errBuf.String(), err)
	}
	return nil
}

func (t *Table) loadFromDataplane() {
	slog.Debug("start load from dataplane", "ipVersion", t.ipVersion)
	hashes, rules, err := t.getHashesAndRulesFromDataplane()
	if err != nil {
		slog.Error("Get hashes and rules from Dataplane failed", "err", err)
		return
	}
	t.chainHashesFromDataplane = hashes
	t.rawRulesOfDefaultChainFromDataplane = rules
	t.inSyncWithDataplane = true
	slog.Debug("finish load from dataplane", "chainHashesFromDataplane", t.chainHashesFromDataplane,
		"rawRulesOfDefaultChainFromDataplane", t.rawRulesOfDefaultChainFromDataplane, "ipVersion", t.ipVersion)
}

func (t *Table) getHashesAndRulesFromDataplane() (map[string][]string, map[string][]string, error) {
	retries := 3
	retryDelay := 100 * time.Millisecond

	for {
		hashes, rules, err := t.attemptToGetHashesAndRulesFromDataplane()
		if err != nil {
			slog.Warn("Get hashes and rules from Dataplane failed. Retrying", "table", t.name, "err", err)
			if retries > 0 {
				retries--
				time.Sleep(retryDelay)
				retryDelay *= 2
			} else {
				return nil, nil, err
			}
			continue
		}
		return hashes, rules, nil
	}
}

func (t *Table) attemptToGetHashesAndRulesFromDataplane() (map[string][]string, map[string][]string, error) {
	// get command from config
	cmd := exec.Command(t.saveCmd, "-t", t.name)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("error stdout from cmd: %w", err)
	}
	if err = cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("error start cmd: %w", err)
	}
	hashes, rules, err := t.readHashesAndRulesFrom(stdout)
	if err != nil {
		if errKill := cmd.Process.Kill(); errKill != nil {
			err = fmt.Errorf("scanner error: %w. then kill process error: %w", err, errKill)
		}
		return nil, nil, err
	}
	if err = cmd.Wait(); err != nil {
		return nil, nil, fmt.Errorf("error wait cmd: %w", err)
	}
	return hashes, rules, nil
}

// readHashesAndRulesFrom
// hashes contain hashed our rule of chains
// rules contain raw our rule of default chain
func (t *Table) readHashesAndRulesFrom(r io.ReadCloser) (map[string][]string, map[string][]string, error) {
	hashes := make(map[string][]string)
	rules := make(map[string][]string)
	scanner := bufio.NewScanner(r)
	chainHasOurRule := make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Bytes()

		// Look for lines of the form ":chainName - [0:0]", which are jump to user-defined chain
		captures := chainRegexp.FindSubmatch(line)
		if captures != nil {
			chainName := string(captures[1])
			hashes[chainName] = []string{}
			if t.ourChainsRegexp.MatchString(chainName) {
				chainHasOurRule[chainName] = struct{}{}
			}
			continue
		}

		// Look for lines of the form "-A chainName something", which are rules of the chain
		captures = ruleAppendRegexp.FindSubmatch(line)
		if captures == nil {
			//slog.Debug("Not an append rule", "line", string(line))
			continue
		}
		chainName := string(captures[1])

		hash := ""
		// Find our rules
		captures = t.hashCommentRegexp.FindSubmatch(line)
		if captures != nil {
			hash = string(captures[1])
		}
		hashes[chainName] = append(hashes[chainName], hash)

		// Get our rules of default chain
		if !t.ourChainsRegexp.MatchString(chainName) {
			fullRule := "-"
			if captures = t.hashCommentRegexp.FindSubmatch(line); captures != nil {
				chainHasOurRule[chainName] = struct{}{}
				fullRule = string(line)
			}
			rules[chainName] = append(rules[chainName], fullRule)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error scanner error: %w", err)
	}

	// Remove all chain has not rules of our
	for chainName := range hashes {
		if _, ok := chainHasOurRule[chainName]; !ok {
			delete(hashes, chainName)
		}
	}
	// Remove all rules has not rules of our
	for chainName := range rules {
		if _, ok := chainHasOurRule[chainName]; !ok {
			delete(rules, chainName)
		}
	}
	return hashes, rules, nil
}

func GetMaxCustomChainName(originName string) string {
	if len(originName) > maxNameLength {
		return originName[0:maxNameLength]
	}
	return originName
}
