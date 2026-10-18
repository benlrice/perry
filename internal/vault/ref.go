package vault

import (
	"fmt"
	"sort"
	"strings"
)

// AuthStyles are the allowed auth labels.
var AuthStyles = []string{"basic", "bearer", "token"}

// WantsUser reports whether entries of this kind usually need a username.
func WantsUser(kind string) bool {
	switch strings.ToLower(kind) {
	case "jenkins", "jira", "artifactory":
		return true
	}
	return false
}

// CheckAuth validates the auth style and username of an entry.
func CheckAuth(e Entry) error {
	if e.Auth == "" {
		return nil
	}
	ok := false
	for _, s := range AuthStyles {
		ok = ok || s == e.Auth
	}
	if !ok {
		return fmt.Errorf("auth must be basic, bearer or token, got %q", e.Auth)
	}
	if e.Auth == "basic" && e.Username == "" {
		return fmt.Errorf("auth basic needs a username (set with: perry edit %s --set-user U)", e.Host)
	}
	return nil
}

// Fields are the valid ref suffixes.
var Fields = []string{"secret", "username", "host", "kind", "notes"}

func validField(f string) bool {
	for _, x := range Fields {
		if x == f {
			return true
		}
	}
	return false
}

// Field returns the named field of the entry.
func (e Entry) Field(name string) string {
	switch name {
	case "username":
		return e.Username
	case "host":
		return e.Host
	case "kind":
		return e.Kind
	case "notes":
		return e.Notes
	}
	return e.Secret
}

// Ref is a resolved reference.
type Ref struct {
	Entry Entry
	Field string // secret when not given
	Label string // the ref without a trailing :field
}

func (d *Data) match(ref, kind string) (int, error) {
	var idx []int
	for i, e := range d.Entries {
		if (e.Host == ref || e.Kind == ref) && (kind == "" || e.Kind == kind) {
			idx = append(idx, i)
		}
	}
	switch len(idx) {
	case 0:
		return -1, fmt.Errorf("no entry matches %q", ref)
	case 1:
		return idx[0], nil
	}
	seen := map[string]bool{}
	var hosts []string
	for _, i := range idx {
		if h := d.Entries[i].Host; !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	return -1, fmt.Errorf("ambiguous ref %q; candidates: %s", ref, strings.Join(hosts, ", "))
}

// ResolveRef resolves <host-or-kind>[:field], optionally narrowed by kind.
// Split at the last colon. If the base resolves, the suffix must be a field.
// If it does not, try the whole ref as a host (so h:8080 works).
func (d *Data) ResolveRef(ref, kind string) (Ref, error) {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		n, err := d.match(ref, kind)
		if err != nil {
			return Ref{}, err
		}
		return Ref{d.Entries[n], "secret", ref}, nil
	}
	base, suffix := ref[:i], ref[i+1:]
	n, baseErr := d.match(base, kind)
	if baseErr == nil {
		if !validField(suffix) {
			return Ref{}, fmt.Errorf("unknown field %q in ref %q", suffix, ref)
		}
		return Ref{d.Entries[n], suffix, base}, nil
	}
	n, wholeErr := d.match(ref, kind)
	if wholeErr == nil {
		return Ref{d.Entries[n], "secret", ref}, nil
	}
	if validField(suffix) {
		return Ref{}, baseErr
	}
	return Ref{}, wholeErr
}
