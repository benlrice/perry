package perry

import (
	"fmt"
	"time"

	"github.com/benlrice/perry/internal/vault"
)

const defaultTTL = 8 * time.Hour

func cmdKeygen(args []string) error {
	fs := flagSet("keygen")
	out := fs.String("out", "", "")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("unexpected argument %q", pos[0])
	}
	rcpt, err := vault.Keygen(*out, prompter)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, rcpt)
	return nil
}

func cmdUnlock(args []string) error {
	fs := flagSet("unlock")
	ttl := fs.Duration("ttl", defaultTTL, "")
	until := fs.String("until", "", "")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("unexpected argument %q", pos[0])
	}
	if wasSet(fs, "ttl") && *until != "" {
		return usageErrorf("--ttl and --until are mutually exclusive")
	}
	d := *ttl
	if *until != "" {
		t, err := time.ParseInLocation("15:04", *until, time.Local)
		if err != nil {
			return usageErrorf("--until needs HH:MM, got %q", *until)
		}
		n := time.Now()
		next := time.Date(n.Year(), n.Month(), n.Day(), t.Hour(), t.Minute(), 0, 0, time.Local)
		if !next.After(n) {
			next = next.AddDate(0, 0, 1)
		}
		d = next.Sub(n)
	}
	if d <= 0 {
		return usageErrorf("--ttl must be positive")
	}
	exp, err := vault.Unlock(d, prompter)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "unlocked until %s\n", exp.Format(time.RFC3339))
	return nil
}

func cmdLock(args []string) error {
	if len(args) > 0 {
		return usageErrorf("lock takes no arguments")
	}
	return vault.CacheDrop()
}

func cmdStatus(args []string) error {
	if len(args) > 0 {
		return usageErrorf("status takes no arguments")
	}
	st, err := vault.CurrentStatus()
	if err != nil {
		return err
	}
	switch {
	case !st.Protected:
		fmt.Fprintln(stdout, "no passphrase on identity; always available")
	case st.Unlocked:
		fmt.Fprintf(stdout, "unlocked until %s (%s left)\n", st.Expiry.Format(time.RFC3339), time.Until(st.Expiry).Round(time.Second))
	default:
		fmt.Fprintln(stdout, "locked")
		return &exitError{code: 3}
	}
	return nil
}

func cmdRekey(args []string) error {
	fs := flagSet("rekey")
	from := fs.String("from", "", "")
	to := fs.String("to", "", "")
	noBackup := fs.Bool("no-backup", false, "")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("unexpected argument %q", pos[0])
	}
	res, err := vault.Rekey(vault.RekeyOptions{From: *from, To: *to, NoBackup: *noBackup}, prompter)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "rekeyed %d entries to %s (single recipient); run `perry unlock` if protected\n", res.Entries, vault.StorePath())
	if res.Backups {
		fmt.Fprintf(stderr, "perry: rekey: warning: %s.bak and the recipients .bak hold the old encryption; delete them when you no longer need them (or use --no-backup)\n", vault.StorePath())
	}
	return nil
}
