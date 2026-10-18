package leak

import (
	"encoding/base64"
	"testing"

	"github.com/benlrice/perry/internal/vault"
)

func data() *vault.Data {
	return &vault.Data{Version: 1, Entries: []vault.Entry{
		{Host: "a.example.com", Kind: "api", Username: "alice", Secret: "tok-Abc123xyz789"},
		{Host: "s.example.com", Kind: "web", Secret: "cat"},
	}}
}

func TestIn(t *testing.T) {
	d := data()
	cases := []struct {
		name  string
		texts []string
		want  bool
	}{
		{"none", nil, false},
		{"clean", []string{"hello", "world"}, false},
		{"literal in second text", []string{"hello", "x tok-Abc123xyz789 y"}, true},
		{"base64", []string{base64.StdEncoding.EncodeToString([]byte("alice:tok-Abc123xyz789"))}, true},
		{"short secret whole word", []string{"the cat sat"}, true},
		{"short secret inside word", []string{"category"}, false},
	}
	for _, c := range cases {
		if got := In(d, c.texts...); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	if In(&vault.Data{}, "tok-Abc123xyz789") {
		t.Error("empty store matched")
	}
}
