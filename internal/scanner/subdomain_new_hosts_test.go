package scanner

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNewSubdomainNames(t *testing.T) {
	before := map[string]bool{
		"apex.example":         true,
		"www.example":          true,
		"kept.example":         true,
		"vhost.example":        true, // inserted by the vhost path, already stored
		"pruned.example":       true, // removed by pruning before the notify
	}
	after := map[string]bool{
		"apex.example":       true,
		"www.example":        true,
		"kept.example":       true,
		"vhost.example":      true,
		"deep.example":       true, // apex resolveAll
		"recursive.example":  true, // recursiveEnum
		"probe.example":      true, // upsertVhost
		// pruned.example is absent: pruning removed it, so it is not a new name.
	}

	got := newSubdomainNames(before, after)
	want := []string{"deep.example", "probe.example", "recursive.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("newSubdomainNames = %v, want %v", got, want)
	}
}

func TestNewSubdomainNamesEmpty(t *testing.T) {
	if got := newSubdomainNames(nil, nil); len(got) != 0 {
		t.Fatalf("empty diff = %v, want empty", got)
	}
	if got := newSubdomainNames(map[string]bool{"a": true}, map[string]bool{"a": true}); len(got) != 0 {
		t.Fatalf("no-change diff = %v, want empty", got)
	}
}

func TestNewSubdomainMetadata(t *testing.T) {
	hosts := []string{"a.example", "b.example", "c.example"}
	raw := newSubdomainMetadata(hosts, len(hosts))
	var meta struct {
		Hosts     []string `json:"hosts"`
		Truncated bool     `json:"truncated"`
		Total     int      `json:"total"`
	}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatalf("metadata is not valid JSON: %v (%s)", err, raw)
	}
	if !reflect.DeepEqual(meta.Hosts, hosts) {
		t.Fatalf("hosts = %v, want %v", meta.Hosts, hosts)
	}
	if meta.Truncated || meta.Total != 3 {
		t.Fatalf("truncated=%v total=%d, want false and 3", meta.Truncated, meta.Total)
	}
	if strings.Contains(raw, "\n") {
		t.Fatalf("metadata should be compact JSON: %s", raw)
	}
}

func TestNewSubdomainMetadataTruncation(t *testing.T) {
	hosts := make([]string, newSubdomainMetadataCap+10)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%04d.example", i)
	}
	raw := newSubdomainMetadata(hosts, len(hosts))
	var meta struct {
		Hosts     []string `json:"hosts"`
		Truncated bool     `json:"truncated"`
		Total     int      `json:"total"`
	}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Hosts) != newSubdomainMetadataCap {
		t.Fatalf("stored hosts = %d, want %d", len(meta.Hosts), newSubdomainMetadataCap)
	}
	if !meta.Truncated || meta.Total != len(hosts) {
		t.Fatalf("truncated=%v total=%d, want true and %d", meta.Truncated, meta.Total, len(hosts))
	}
	// The stored slice must be the leading names in stable order.
	if meta.Hosts[0] != "h0000.example" || meta.Hosts[len(meta.Hosts)-1] != "h0499.example" {
		t.Fatalf("unexpected stored range: %s .. %s", meta.Hosts[0], meta.Hosts[len(meta.Hosts)-1])
	}
}

func TestNewSubdomainMetadataEmpty(t *testing.T) {
	raw := newSubdomainMetadata(nil, 0)
	if raw != `{"hosts":[],"truncated":false,"total":0}` {
		t.Fatalf("empty metadata = %s", raw)
	}
}
