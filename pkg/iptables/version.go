package iptables

import (
	"fmt"
	"os/exec"
	"regexp"

	"github.com/bamboo-firewall/agent/pkg/generictables"
)

type version struct {
	major int
	minor int
	patch int
}

var (
	// v1dot6dot0 version 1.6.0, when --wait support second
	v1dot6dot0 = version{
		major: 1,
		minor: 6,
		patch: 0,
	}
	// v1dot4dot20 version 1.4.20, when --wait was support
	v1dot4dot20 = version{
		major: 1,
		minor: 4,
		patch: 20,
	}
)

func (v version) isGTE(targetVersion version) bool {
	if v.major > targetVersion.major {
		return true
	} else if v.major == targetVersion.major && v.minor > targetVersion.minor {
		return true
	} else if v.major == targetVersion.major && v.minor == targetVersion.minor && v.patch >= targetVersion.patch {
		return true
	}
	return false
}

func getIptablesVersion(ipVersion int) (version, string, error) {
	iptablesCommand := getIptablesCommand(ipVersion)
	cmd := exec.Command(iptablesCommand, "--version")
	out, err := cmd.Output()
	if err != nil {
		return version{}, "", fmt.Errorf("failed to get iptables version: %w", err)
	}
	return extractIptablesVersion(string(out))
}

func getIptablesCommand(ipVersion int) string {
	if ipVersion == generictables.IPFamily6 {
		return "ip6tables"
	}
	return "iptables"
}

// getIptablesVersion returns the first three components of the iptables version
// and the operating mode (e.g. nf_tables or legacy)
// e.g. "iptables v1.3.66" would return (1, 3, 66, legacy, nil)
func extractIptablesVersion(str string) (version, string, error) {
	versionMatcher := regexp.MustCompile(`v([0-9]+\.[0-9]+\.[0-9]+)(?:\s+\((\w+)\))?`)
	result := versionMatcher.FindStringSubmatch(str)
	if len(result) == 0 {
		return version{}, "", fmt.Errorf("no iptables version found in string: %s", str)
	}

	var major, minor, patch int
	_, err := fmt.Sscanf(result[1], "%d.%d.%d", &major, &minor, &patch)
	if err != nil {
		return version{}, "", fmt.Errorf("error extracting version: %s error: %w", result[1], err)
	}

	var mode string
	if result[2] != "" {
		mode = modeNFT
	} else {
		mode = modeLegacy
	}
	return version{
		major: major,
		minor: minor,
		patch: patch,
	}, mode, nil
}
