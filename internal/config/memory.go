package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

const bytesPerMiB = 1024 * 1024

type cgroupMemoryFiles struct {
	limit string
	used  string
}

var cgroupMemoryCandidates = []cgroupMemoryFiles{
	// cgroup v2 (Docker, current Kubernetes and systemd).
	{limit: "/sys/fs/cgroup/memory.max", used: "/sys/fs/cgroup/memory.current"},
	// Common cgroup v1 layouts.
	{limit: "/sys/fs/cgroup/memory/memory.limit_in_bytes", used: "/sys/fs/cgroup/memory/memory.usage_in_bytes"},
	{limit: "/sys/fs/cgroup/memory.limit_in_bytes", used: "/sys/fs/cgroup/memory.usage_in_bytes"},
}

// CgroupMemoryStats returns the memory currently charged to this container and
// its hard limit. Unlike /proc/meminfo or gopsutil's host-wide counters, this
// includes Reconner's child processes (Chromium, nuclei, sqlmap, dirsearch) and
// therefore describes the memory pressure that can actually OOM the service.
func CgroupMemoryStats() (usedMB, limitMB int, ok bool) {
	return readCgroupMemoryStats(os.ReadFile)
}

func readCgroupMemoryStats(readFile func(string) ([]byte, error)) (usedMB, limitMB int, ok bool) {
	for _, candidate := range cgroupMemoryCandidates {
		limitRaw, err := readFile(candidate.limit)
		if err != nil {
			continue
		}
		limitBytes, valid := parseCgroupBytes(limitRaw, true)
		if !valid {
			continue
		}
		usedRaw, err := readFile(candidate.used)
		if err != nil {
			continue
		}
		usedBytes, valid := parseCgroupBytes(usedRaw, false)
		if !valid {
			continue
		}
		// Round the limit up so a sub-MiB remainder is not silently discarded;
		// usage is a measurement and can be rounded down.
		limitMB = int((limitBytes + bytesPerMiB - 1) / bytesPerMiB)
		usedMB = int(usedBytes / bytesPerMiB)
		return usedMB, limitMB, limitMB > 0
	}
	return 0, 0, false
}

func parseCgroupBytes(raw []byte, isLimit bool) (uint64, bool) {
	value := strings.TrimSpace(string(raw))
	if value == "" || value == "max" {
		return 0, false
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	// cgroup v1 represents "unlimited" with a huge sentinel close to MaxInt64.
	if isLimit && n >= 1<<60 {
		return 0, false
	}
	return n, true
}

func detectHostTotalMemMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 4096
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		if kb, err := strconv.Atoi(fields[1]); err == nil && kb > 0 {
			return kb / 1024
		}
	}
	return 4096
}

// detectTotalMemMB sizes Reconner against the smaller of host RAM and the
// container cgroup limit. A 2 GiB container on a 64 GiB host must behave like a
// 2 GiB machine, not auto-tune itself for the host and get OOM-killed.
func detectTotalMemMB() int {
	hostMB := detectHostTotalMemMB()
	_, limitMB, ok := CgroupMemoryStats()
	if ok && limitMB > 0 && limitMB < hostMB {
		return limitMB
	}
	return hostMB
}
