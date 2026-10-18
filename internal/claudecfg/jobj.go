package claudecfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jobj is a JSON object that keeps key order and raw values, so keys and
// unrelated values stay byte for byte.
type jobj struct {
	keys []string
	vals map[string]json.RawMessage
}

func newObj() *jobj { return &jobj{vals: map[string]json.RawMessage{}} }

func parseObj(raw []byte) (*jobj, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	o := newObj()
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := o.vals[key]; !dup {
			o.keys = append(o.keys, key)
		}
		o.vals[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("trailing data after JSON object")
	}
	return o, nil
}

func (o *jobj) has(k string) bool { _, ok := o.vals[k]; return ok }

func (o *jobj) set(k string, v json.RawMessage) {
	if !o.has(k) {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *jobj) del(k string) {
	delete(o.vals, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			return
		}
	}
}

// render writes the object with the given indent unit at nesting level.
func (o *jobj) render(indent string, level int) json.RawMessage {
	if len(o.keys) == 0 {
		return json.RawMessage("{}")
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	in := strings.Repeat(indent, level+1)
	for i, k := range o.keys {
		kb, _ := json.Marshal(k)
		b.WriteString(in)
		b.Write(kb)
		b.WriteString(": ")
		b.Write(o.vals[k])
		if i < len(o.keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString(strings.Repeat(indent, level))
	b.WriteByte('}')
	return b.Bytes()
}

// objAt returns the object under key, creating an empty one when missing.
func (o *jobj) objAt(key string) (*jobj, error) {
	raw, ok := o.vals[key]
	if !ok {
		return newObj(), nil
	}
	sub, err := parseObj(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not a JSON object", key)
	}
	return sub, nil
}

// arrAt returns the raw elements under key; a missing key is an empty list.
func (o *jobj) arrAt(key string) ([]json.RawMessage, error) {
	raw, ok := o.vals[key]
	if !ok {
		return nil, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("%q is not a JSON array", key)
	}
	return arr, nil
}

// renderArr writes a list with the indent unit at nesting level.
func renderArr(items []json.RawMessage, indent string, level int) json.RawMessage {
	if len(items) == 0 {
		return json.RawMessage("[]")
	}
	var b bytes.Buffer
	b.WriteString("[\n")
	in := strings.Repeat(indent, level+1)
	for i, it := range items {
		b.WriteString(in)
		b.Write(it)
		if i < len(items)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString(strings.Repeat(indent, level))
	b.WriteByte(']')
	return b.Bytes()
}

// detectIndent returns the indent unit of the first indented key line.
func detectIndent(text string) string {
	for _, l := range strings.Split(text, "\n") {
		trim := strings.TrimLeft(l, " \t")
		if len(trim) > 0 && len(trim) < len(l) && trim[0] == '"' {
			return l[:len(l)-len(trim)]
		}
	}
	return "  "
}
