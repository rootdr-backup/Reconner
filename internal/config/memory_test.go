package config

import (
	"fmt"
	"testing"
)

func memoryReader(values map[string]string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if value, ok := values[path]; ok {
			return []byte(value), nil
		}
		return nil, fmt.Errorf("not found: %s", path)
	}
}

func TestReadCgroupV2MemoryStats(t *testing.T) {
	read := memoryReader(map[string]string{
		"/sys/fs/cgroup/memory.max":     "2147483648\n",
		"/sys/fs/cgroup/memory.current": "805306368\n",
	})
	used, limit, ok := readCgroupMemoryStats(read)
	if !ok || used != 768 || limit != 2048 {
		t.Fatalf("cgroup v2 stats = used:%d limit:%d ok:%v", used, limit, ok)
	}
}

func TestReadCgroupV1AndUnlimitedMemory(t *testing.T) {
	v1 := memoryReader(map[string]string{
		"/sys/fs/cgroup/memory/memory.limit_in_bytes": "3221225472",
		"/sys/fs/cgroup/memory/memory.usage_in_bytes": "1073741824",
	})
	used, limit, ok := readCgroupMemoryStats(v1)
	if !ok || used != 1024 || limit != 3072 {
		t.Fatalf("cgroup v1 stats = used:%d limit:%d ok:%v", used, limit, ok)
	}

	unlimited := memoryReader(map[string]string{
		"/sys/fs/cgroup/memory.max":     "max",
		"/sys/fs/cgroup/memory.current": "1048576",
	})
	if _, _, ok := readCgroupMemoryStats(unlimited); ok {
		t.Fatal("an unlimited cgroup must fall back to host memory")
	}
}
