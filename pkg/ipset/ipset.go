package ipset

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"regexp"
	"time"

	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/net"
)

const (
	inetV4 = "inet"
	inetV6 = "inet6"
)

const ipsetCmd = "ipset"

type IPSet struct {
	ipVersion int
	// setFromDatastore network sets from datastore
	setFromDatastore map[string]map[string]struct{}
	// setFromDataplane ipsets from dataplane
	setFromDataplane map[string]map[string]struct{}

	ourSetRegex    *regexp.Regexp
	ourMemberRegex *regexp.Regexp

	// inSyncWithDataplane get ipset from dataplane done
	inSyncWithDataplane bool

	inetVersion string

	ipsetCmd string
}

func NewIPSet(ipVersion int) (*IPSet, error) {
	if err := checkIPSetCmd(); err != nil {
		return nil, err
	}
	set := &IPSet{
		ourMemberRegex: regexp.MustCompile(`^add (` + namePrefix + `[a-zA-Z0-9_-]+) (\S+)(.*)$`),
		ipsetCmd:       ipsetCmd,
	}

	if ipVersion == generictables.IPFamily6 {
		set.inetVersion = inetV6
		set.ipVersion = generictables.IPFamily6
	} else {
		set.inetVersion = inetV4
		set.ipVersion = generictables.IPFamily4
	}
	set.ourSetRegex = regexp.MustCompile(fmt.Sprintf(`^create (%s[a-zA-Z0-9_-]+) ([a-z:,]+) (family) (%s) (.*)$`, namePrefix, set.inetVersion))
	return set, nil
}

func checkIPSetCmd() error {
	_, err := exec.LookPath(ipsetCmd)
	if err != nil {
		return errors.New("ipset not found in $PATH")
	}
	return nil
}

func (i *IPSet) GetIPVersion() int {
	return i.ipVersion
}

func (i *IPSet) UpdateIPSet(ipset map[string]map[string]struct{}) {
	i.setFromDatastore = ipset
}

func (i *IPSet) Apply() {
	if len(i.setFromDatastore) == 0 {
		return
	}

	if !i.inSyncWithDataplane {
		i.loadFromDataplane()
	}

	retries := 3
	retryDelay := 100 * time.Millisecond

	for {
		err := i.apply()
		if err != nil {
			slog.Warn("apply ipset failed. Retrying", "err", err)
			if retries > 0 {
				retries--
				time.Sleep(retryDelay)
				retryDelay *= 2
			} else {
				slog.Error("apply ipset fail after retry.", "err", err)
				break
			}
			continue
		}
		break
	}
	i.inSyncWithDataplane = false
}

func (i *IPSet) apply() error {
	buf := bytes.NewBuffer(nil)

	cloneSetFromDataplane := make(map[string]map[string]struct{})
	for k, vv := range i.setFromDataplane {
		cloneSetFromDataplane[k] = make(map[string]struct{})
		for v := range vv {
			cloneSetFromDataplane[k][v] = struct{}{}
		}
	}

	for name, members := range i.setFromDatastore {
		// create ipset
		if _, ok := cloneSetFromDataplane[name]; !ok {
			buf.WriteString(fmt.Sprintf("create %s hash:net family %s\n", name, i.inetVersion))
		}
		// create new members for ipset
		for member := range members {
			if _, ok := cloneSetFromDataplane[name][member]; !ok {
				buf.WriteString(fmt.Sprintf("add %s %s\n", name, member))
			} else {
				delete(cloneSetFromDataplane[name], member)
			}
		}
		// del unused members
		for member := range cloneSetFromDataplane[name] {
			buf.WriteString(fmt.Sprintf("del %s %s\n", name, member))
		}
		// mark ipset done
		delete(cloneSetFromDataplane, name)
	}
	// destroy unused ipset
	for name := range cloneSetFromDataplane {
		buf.WriteString(fmt.Sprintf("destroy %s\n", name))
	}
	if buf.Len() == 0 {
		return nil
	}
	return i.execRestore(buf)
}

func (i *IPSet) execRestore(buf *bytes.Buffer) error {
	contentBytes := buf.Next(buf.Len())

	var outputBuf, errBuf bytes.Buffer
	cmd := exec.Command(i.ipsetCmd, "restore")
	cmd.Stdin = bytes.NewReader(contentBytes)
	cmd.Stdout = &outputBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func (i *IPSet) loadFromDataplane() {
	ipsets, err := i.getIPSetFromDataplane()
	if err != nil {
		slog.Error("Get ipsets from Dataplane failed", "err", err)
		return
	}
	i.setFromDataplane = ipsets
	i.inSyncWithDataplane = true
}

func (i *IPSet) getIPSetFromDataplane() (map[string]map[string]struct{}, error) {
	retries := 3
	retryDelay := 100 * time.Millisecond

	for {
		ipsets, err := i.attemptToGetIPSetFromDataplane()
		if err != nil {
			slog.Warn("Get ipsets from Dataplane failed. Retrying", "err", err)
			if retries > 0 {
				retries--
				time.Sleep(retryDelay)
				retryDelay *= 2
			} else {
				return nil, err
			}
			continue
		}
		return ipsets, nil
	}
}

func (i *IPSet) attemptToGetIPSetFromDataplane() (map[string]map[string]struct{}, error) {
	cmd := exec.Command(i.ipsetCmd, "save")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error stdout from cmd: %w", err)
	}
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting cmd: %w", err)
	}
	ipsets, err := i.readIPSetFrom(stdout)
	if err != nil {
		if errKill := cmd.Process.Kill(); errKill != nil {
			err = fmt.Errorf("scanner error: %w. then kill process error: %w", err, errKill)
		} else {
			err = fmt.Errorf("error scanner: %w", err)
		}
		return nil, err
	}
	if err = cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error wait cmd: %w", err)
	}
	return ipsets, nil
}

func (i *IPSet) readIPSetFrom(r io.ReadCloser) (map[string]map[string]struct{}, error) {
	ipsets := make(map[string]map[string]struct{})

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		captures := i.ourSetRegex.FindStringSubmatch(line)
		if captures != nil {
			ipsets[captures[1]] = make(map[string]struct{})
			continue
		}

		captures = i.ourMemberRegex.FindStringSubmatch(line)
		if captures != nil {
			if ipsets[captures[1]] == nil {
				continue
			}
			_, ipnet, err := net.ParseCIDROrIP(captures[2])
			if err != nil {
				slog.Warn("parse ip false", "ip", captures[2], "err", err)
				continue
			}
			ipsets[captures[1]][ipnet.String()] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ipsets, nil
}
