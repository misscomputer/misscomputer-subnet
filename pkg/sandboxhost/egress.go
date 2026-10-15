// SPDX-License-Identifier: AGPL-3.0-only

package sandboxhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"reflect"
	"strings"
)

// Destinations the engine slice must never reach, in addition to every
// local address of the host (rule 2 below).
var egressDenied = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
	"::/127", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "fc00::/7", "fe80::/10", "ff00::/8",
}

// listEgress returns `nft -j list table inet <name>` (json) or
// `nft -a list table inet <name>` (text with rule handles). The JSON is the
// structural source of truth; nft 1.0.9 omits the socket cgroupv2 level from
// JSON, so the text listing confirms "level 1" on every rule and is bound to
// the JSON by rule handle.
func (h Host) listEgress(name string, asJSON bool) (string, error) {
	if h.ListNFTable != nil {
		return h.ListNFTable(name, asJSON)
	}
	args := []string{"-a", "list", "table", "inet", name}
	if asJSON {
		args = []string{"-j", "list", "table", "inet", name}
	}
	out, err := exec.Command("nft", args...).Output()
	if err != nil {
		return "", fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

type nftObject map[string]json.RawMessage

// egressRestricted accepts exactly the table provision-disposable.sh
// renders and nothing else (INT-27-07): one output filter chain with policy
// accept and exactly four rules, in order, each beginning with the engine
// slice's socket cgroupv2 match:
//
//  1. ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept
//  2. fib daddr type local counter reject with icmpx admin-prohibited
//  3. ip daddr { set } counter reject with icmpx admin-prohibited
//  4. ip6 daddr { set } counter reject with icmpx admin-prohibited
//
// Any other table object, rule, statement, qualifier, operator, verdict or
// comment is refused, and the two sets must contain every denied prefix.
func egressRestricted(jsonListing, textListing, table, engineSlice string) error {
	var doc struct {
		Nftables []nftObject `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(jsonListing), &doc); err != nil {
		return fmt.Errorf("egress table JSON: %w", err)
	}
	var rules []json.RawMessage
	var handles []int
	chains := 0
	for _, object := range doc.Nftables {
		if len(object) != 1 {
			return errors.New("egress table JSON object with several keys")
		}
		for kind, body := range object {
			switch kind {
			case "metainfo":
			case "table":
				var t struct {
					Family, Name string
					Handle       int
				}
				if err := strictDecode(body, &t); err != nil || t.Family != "inet" || t.Name != table {
					return fmt.Errorf("unexpected table %s", body)
				}
			case "chain":
				chains++
				var c struct {
					Family, Table, Name, Type, Hook, Policy string
					Handle, Prio                            int
				}
				if err := strictDecode(body, &c); err != nil || c.Name != "output" || c.Type != "filter" ||
					c.Hook != "output" || c.Prio != 0 || c.Policy != "accept" || c.Table != table {
					return fmt.Errorf("egress chain is not the output filter chain with policy accept: %s", body)
				}
			case "rule":
				var r struct {
					Family, Table, Chain string
					Handle               int
					Expr                 json.RawMessage
				}
				if err := strictDecode(body, &r); err != nil || r.Chain != "output" || r.Table != table {
					return fmt.Errorf("unexpected rule object (comments and other members are refused): %s", body)
				}
				rules = append(rules, r.Expr)
				handles = append(handles, r.Handle)
			default:
				return fmt.Errorf("egress table holds a %s object", kind)
			}
		}
	}
	if chains != 1 {
		return fmt.Errorf("egress table has %d chains, want exactly the output chain", chains)
	}
	if len(rules) != 4 {
		return fmt.Errorf("egress chain has %d rules, want exactly 4", len(rules))
	}
	slice := engineSlice
	socket := match(map[string]any{"socket": map[string]any{"key": "cgroupv2"}}, slice)
	expect := [][]any{
		{socket, match(payload("ip", "daddr"), "127.0.0.53"), match(map[string]any{"meta": map[string]any{"key": "l4proto"}}, map[string]any{"set": []any{"tcp", "udp"}}),
			match(payload("th", "dport"), float64(53)), map[string]any{"accept": nil}},
		{socket, match(map[string]any{"fib": map[string]any{"result": "type", "flags": []any{"daddr"}}}, "local"), counterAny{}, reject()},
	}
	for i, want := range expect {
		if err := sameExprs(rules[i], want); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	covered := map[netip.Prefix]bool{}
	for i, family := range []string{"ip", "ip6"} {
		set, err := prefixSetRule(rules[2+i], socket, family)
		if err != nil {
			return fmt.Errorf("rule %d: %w", 3+i, err)
		}
		for _, p := range set {
			covered[p] = true
		}
	}
	for _, text := range egressDenied {
		if !covered[netip.MustParsePrefix(text).Masked()] {
			return fmt.Errorf("engine egress does not reject %s", text)
		}
	}
	return textMatches(textListing, table, slice, handles)
}

// textMatches requires the `nft -a list` text to consist of the table and
// chain framing plus exactly the four rules, each at cgroupv2 level 1 for the
// slice by name, carrying the rule handles of the JSON listing in order. Any
// other line (flags, comments, extra objects) is refused (INT-33-01), and the
// handles bind the two listings to the same rules (INT-33-02).
func textMatches(textListing, table, slice string, handles []int) error {
	want := `socket cgroupv2 level 1 "` + slice + `" `
	var seen []int
	for _, raw := range strings.Split(textListing, "\n") {
		line := strings.TrimSpace(raw)
		body, handle, hasHandle := strings.Cut(line, " # handle ")
		switch {
		case line == "" || line == "}":
		case hasHandle && body == "table inet "+table+" {":
		case hasHandle && body == "chain output {":
		case line == "type filter hook output priority filter; policy accept;":
		case hasHandle && strings.HasPrefix(body, want):
			var n int
			if _, err := fmt.Sscanf(handle, "%d", &n); err != nil || fmt.Sprint(n) != handle {
				return fmt.Errorf("rule line with malformed handle: %s", line)
			}
			seen = append(seen, n)
		default:
			return fmt.Errorf("unexpected line in the egress table text listing: %s", line)
		}
	}
	if !reflect.DeepEqual(seen, handles) {
		return fmt.Errorf("text listing rule handles %v differ from the JSON listing %v", seen, handles)
	}
	return nil
}

// strictDecode decodes into v, refusing unknown members.
func strictDecode(raw json.RawMessage, v any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func match(left, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
}

func payload(protocol, field string) map[string]any {
	return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
}

func reject() map[string]any {
	return map[string]any{"reject": map[string]any{"type": "icmpx", "expr": "admin-prohibited"}}
}

// counterAny stands for an anonymous counter statement with any values.
type counterAny struct{}

func isCounter(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	c, ok := m["counter"].(map[string]any)
	if !ok || len(c) != 2 {
		return false
	}
	_, packets := c["packets"].(float64)
	_, bytes := c["bytes"].(float64)
	return packets && bytes
}

func sameExprs(raw json.RawMessage, want []any) error {
	var got []any
	if err := json.Unmarshal(raw, &got); err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("has %d statements, want %d: %s", len(got), len(want), raw)
	}
	for i := range want {
		if _, ok := want[i].(counterAny); ok {
			if !isCounter(got[i]) {
				return fmt.Errorf("statement %d is not an anonymous counter: %s", i+1, raw)
			}
			continue
		}
		if !reflect.DeepEqual(got[i], normalize(want[i])) {
			return fmt.Errorf("statement %d differs from the provisioned form: %s", i+1, raw)
		}
	}
	return nil
}

// normalize round-trips a Go value through JSON so it compares equal to a
// decoded listing (numbers as float64, nested maps as map[string]any).
func normalize(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

func prefixSetRule(raw json.RawMessage, socket map[string]any, family string) ([]netip.Prefix, error) {
	var got []any
	if err := json.Unmarshal(raw, &got); err != nil {
		return nil, err
	}
	if len(got) != 4 || !reflect.DeepEqual(got[0], normalize(socket)) || !isCounter(got[2]) || !reflect.DeepEqual(got[3], normalize(reject())) {
		return nil, fmt.Errorf("is not <socket match> %s daddr { set } counter reject: %s", family, raw)
	}
	m, ok := got[1].(map[string]any)["match"].(map[string]any)
	if !ok || len(m) != 3 || m["op"] != "==" || !reflect.DeepEqual(m["left"], normalize(payload(family, "daddr"))) {
		return nil, fmt.Errorf("does not match %s daddr with ==: %s", family, raw)
	}
	set, ok := m["right"].(map[string]any)
	elements, ok2 := set["set"].([]any)
	if !ok || !ok2 || len(set) != 1 {
		return nil, fmt.Errorf("right side is not an anonymous set: %s", raw)
	}
	var prefixes []netip.Prefix
	for _, element := range elements {
		var text string
		switch e := element.(type) {
		case string:
			text = e
		case map[string]any:
			p, ok := e["prefix"].(map[string]any)
			addr, okAddr := p["addr"].(string)
			length, okLen := p["len"].(float64)
			if !ok || len(e) != 1 || len(p) != 2 || !okAddr || !okLen {
				return nil, fmt.Errorf("set element %v is not a prefix", element)
			}
			text = fmt.Sprintf("%s/%d", addr, int(length))
		default:
			return nil, fmt.Errorf("set element %v is not a prefix", element)
		}
		if !strings.Contains(text, "/") {
			if addr, err := netip.ParseAddr(text); err == nil {
				text = netip.PrefixFrom(addr, addr.BitLen()).String()
			}
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil || (family == "ip") != prefix.Addr().Is4() {
			return nil, fmt.Errorf("set element %v is not an %s prefix", element, family)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
