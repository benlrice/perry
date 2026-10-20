package perry

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/benlrice/perry/internal/redact"
	"github.com/benlrice/perry/internal/vault"
)

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func cmdAdd(args []string) error {
	fs := flagSet("add")
	host := fs.String("host", "", "")
	kind := fs.String("kind", "", "")
	user := fs.String("user", "", "")
	auth := fs.String("auth", "", "")
	notes := fs.String("notes", "", "")
	update := fs.Bool("update", false, "")
	var tags stringList
	fs.Var(&tags, "tag", "")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("unexpected argument %q", pos[0])
	}
	if *host == "" || *kind == "" {
		return usageErrorf("--host and --kind are required")
	}

	username := *user
	if !wasSet(fs, "user") && *auth != "bearer" && *auth != "token" {
		switch {
		case isTerminal(stdin):
			fmt.Fprint(stderr, "Username (blank for token-only): ")
			line, _ := readLine(stdin)
			username = strings.TrimSpace(line)
		case *auth == "" && vault.WantsUser(*kind):
			fmt.Fprintf(stderr, "perry: add: warning: kind %s usually needs a username; entry has no username (set with: perry edit %s --set-user U, or pass --user \"\" for token-only)\n", *kind, *host)
		}
	}
	e := vault.Entry{Host: *host, Kind: *kind, Username: username, Auth: *auth, Tags: tags, Notes: *notes}
	if err := vault.CheckAuth(e); err != nil {
		return err
	}
	secret, err := readSecret("Secret: ")
	if err != nil {
		return err
	}
	if secret == "" {
		return errors.New("empty secret")
	}
	if len(secret) < redact.MinLen {
		fmt.Fprintf(stderr, "perry: add: warning: secret is shorter than %d characters; perry finds it only as a whole word and not in encoded forms\n", redact.MinLen)
	}
	if strings.Contains(strings.ToLower(*host), strings.ToLower(secret)) {
		return errors.New("host contains the secret")
	}
	e.Secret = secret
	return vault.Update(func(d *vault.Data) error {
		t := now()
		i := d.Find(e.Host, e.Kind)
		switch {
		case i >= 0 && !*update:
			return fmt.Errorf("entry (%s, %s) exists; use --update to replace", e.Host, e.Kind)
		case i >= 0:
			e.Created, e.Updated = d.Entries[i].Created, t
			d.Entries[i] = e
		default:
			e.Created, e.Updated = t, t
			d.Entries = append(d.Entries, e)
		}
		return nil
	})
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func printEntries(entries []vault.Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Host != entries[j].Host {
			return entries[i].Host < entries[j].Host
		}
		return entries[i].Kind < entries[j].Kind
	})
	var w interface{ Write([]byte) (int, error) } = stdout
	var tw *tabwriter.Writer
	if isTerminal(stdout) {
		tw = tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
		w = tw
	}
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.Host, e.Kind, dash(e.Username), dash(strings.Join(e.Tags, ",")), dash(e.Auth))
	}
	if tw != nil {
		tw.Flush()
	}
}

func cmdList(args []string) error {
	if len(args) > 0 {
		return usageErrorf("list takes no arguments")
	}
	return vault.View(func(d *vault.Data) error {
		printEntries(append([]vault.Entry(nil), d.Entries...))
		return nil
	})
}

func cmdSearch(args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return usageErrorf("usage: perry search KEYWORD")
	}
	kw := strings.ToLower(args[0])
	return vault.View(func(d *vault.Data) error {
		var hit []vault.Entry
		for _, e := range d.Entries {
			text := strings.ToLower(strings.Join(append([]string{e.Host, e.Kind, e.Notes}, e.Tags...), "\n"))
			if strings.Contains(text, kw) {
				hit = append(hit, e)
			}
		}
		printEntries(hit)
		return nil
	})
}

// refArg parses "REF [--kind K]" with the ref on either side of the flag.
func refArg(name string, args []string, _ any) (ref, kind string, err error) {
	fs := flagSet(name)
	k := fs.String("kind", "", "")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return "", "", err
	}
	if len(pos) != 1 {
		return "", "", usageErrorf("usage: perry %s REF [--kind K]", name)
	}
	return pos[0], *k, nil
}

func usageLine(e vault.Entry) string {
	switch e.Auth {
	case "basic":
		return fmt.Sprintf("perry run -- curl -u '{{perry:%s:username}}:{{perry:%s}}' URL", e.Host, e.Host)
	case "bearer":
		return fmt.Sprintf("perry run -- curl -H 'Authorization: Bearer {{perry:%s}}' URL", e.Host)
	case "token":
		return fmt.Sprintf("perry run -- curl -H 'Authorization: token {{perry:%s}}' URL", e.Host)
	}
	return ""
}

func cmdShow(args []string) error {
	ref, kind, err := refArg("show", args, nil)
	if err != nil {
		return err
	}
	return vault.View(func(d *vault.Data) error {
		r, err := d.ResolveRef(ref, kind)
		if err != nil {
			return err
		}
		e := r.Entry
		fmt.Fprintf(stdout, "host: %s\nkind: %s\nuser: %s\nauth: %s\ntags: %s\nnotes: %s\ncreated: %s\nupdated: %s\n",
			e.Host, e.Kind, e.Username, e.Auth, strings.Join(e.Tags, ","), e.Notes, e.Created, e.Updated)
		if u := usageLine(e); u != "" {
			fmt.Fprintf(stdout, "usage: %s\n", u)
		}
		return nil
	})
}

func cmdGet(args []string) error {
	fs := flagSet("get")
	reveal := fs.Bool("reveal", false, "")
	k := fs.String("kind", "", "")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("usage: perry get REF --reveal [--kind K]")
	}
	if !*reveal {
		return errors.New("refusing; --reveal is required")
	}
	if !isTerminal(stdout) {
		return errors.New("refusing; stdout is not a terminal")
	}
	return vault.View(func(d *vault.Data) error {
		r, err := d.ResolveRef(pos[0], *k)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, r.Entry.Field(r.Field))
		return nil
	})
}

func cmdEdit(args []string) error {
	fs := flagSet("edit")
	kind := fs.String("kind", "", "")
	setHost := fs.String("set-host", "", "")
	setKind := fs.String("set-kind", "", "")
	setUser := fs.String("set-user", "", "")
	setAuth := fs.String("set-auth", "", "")
	notes := fs.String("notes", "", "")
	addTag := fs.String("add-tag", "", "")
	rmTag := fs.String("rm-tag", "", "")
	var tags stringList
	fs.Var(&tags, "tag", "")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("usage: perry edit REF [flags]")
	}
	changes := 0
	for _, n := range []string{"set-host", "set-kind", "set-user", "set-auth", "notes", "tag", "add-tag", "rm-tag"} {
		if wasSet(fs, n) {
			changes++
		}
	}
	if changes == 0 {
		return errors.New("nothing to change")
	}
	if (wasSet(fs, "set-host") && *setHost == "") || (wasSet(fs, "set-kind") && *setKind == "") {
		return errors.New("host and kind cannot be empty")
	}
	var edited vault.Entry
	err = vault.Update(func(d *vault.Data) error {
		r, err := d.ResolveRef(pos[0], *kind)
		if err != nil {
			return err
		}
		i := d.Find(r.Entry.Host, r.Entry.Kind)
		e := d.Entries[i]
		if wasSet(fs, "set-host") {
			e.Host = *setHost
		}
		if wasSet(fs, "set-kind") {
			e.Kind = *setKind
		}
		if wasSet(fs, "set-user") {
			e.Username = *setUser
		}
		if wasSet(fs, "set-auth") {
			e.Auth = *setAuth
		}
		if wasSet(fs, "notes") {
			e.Notes = *notes
		}
		if wasSet(fs, "tag") {
			e.Tags = append([]string(nil), tags...)
		}
		if wasSet(fs, "add-tag") {
			e.Tags = appendUnique(e.Tags, *addTag)
		}
		if wasSet(fs, "rm-tag") {
			var keep []string
			for _, t := range e.Tags {
				if t != *rmTag {
					keep = append(keep, t)
				}
			}
			e.Tags = keep
		}
		if strings.Contains(strings.ToLower(e.Host), strings.ToLower(e.Secret)) {
			return errors.New("host contains the secret")
		}
		if (e.Host != d.Entries[i].Host || e.Kind != d.Entries[i].Kind) && d.Find(e.Host, e.Kind) >= 0 {
			return fmt.Errorf("entry (%s, %s) exists", e.Host, e.Kind)
		}
		if err := vault.CheckAuth(e); err != nil {
			return err
		}
		e.Updated = now()
		d.Entries[i] = e
		edited = e
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "edited: %s %s\n", edited.Host, edited.Kind)
	return nil
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func cmdRm(args []string) error {
	ref, kind, err := refArg("rm", args, nil)
	if err != nil {
		return err
	}
	var host, k string
	if err := vault.View(func(d *vault.Data) error {
		r, err := d.ResolveRef(ref, kind)
		host, k = r.Entry.Host, r.Entry.Kind
		return err
	}); err != nil {
		return err
	}
	return vault.Update(func(d *vault.Data) error {
		i := d.Find(host, k)
		if i < 0 {
			return errors.New("entry vanished")
		}
		d.Entries = append(d.Entries[:i], d.Entries[i+1:]...)
		return nil
	})
}
