package sub

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const clashSudokuFeedURL = "http://127.0.0.1:18085/sudoku"

var sudokuPathRoot = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
var sudokuHostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Only an enabled client-assigned row for this local feed opts into Sudoku.
// Arbitrary remote subscriptions must not be treated as this managed listener.
func isClashSudokuFeed(entry externalLinkEntry) bool {
	return entry.Kind == model.ExternalLinkKindSubscription && entry.Value == clashSudokuFeedURL
}

// Per-account LSP nodes are provisioned as individual share links. The raw
// and Xray formats do not consume this local managed entry.
func isClashSudokuGrant(entry externalLinkEntry) bool {
	return entry.Kind == model.ExternalLinkKindLink && entry.Remark == "Sudoku" && strings.HasPrefix(entry.Value, "sudoku://")
}

// Custom routing can replace the default selector. Append the opted-in node to
// an existing manual selector without reordering its choices or editing rules.
func includeSudokuInClashSelectGroup(config map[string]any, name string) {
	proxies, _ := asAnySlice(config["proxies"])
	if !slices.ContainsFunc(proxies, func(item any) bool {
		p, _ := item.(map[string]any)
		return p["name"] == name && p["type"] == "sudoku"
	}) {
		return // A custom configuration or an exhausted account removed the node.
	}
	groups, _ := asAnySlice(config["proxy-groups"])
	first := -1
	included := false
	for i, item := range groups {
		group, _ := item.(map[string]any)
		if group["type"] != "select" {
			continue
		}
		members, _ := asAnySlice(group["proxies"])
		if slices.ContainsFunc(members, func(member any) bool { return member == name }) {
			included = true
			continue
		}
		if group["include-all-proxies"] == true || group["include-all"] == true {
			if oldDefault, compatible := sudokuAutoSelectDefault(group, proxies, name); compatible {
				included = true
				if oldDefault != "" && len(members) == 0 && group["default-selected"] == nil {
					updated := maps.Clone(group)
					updated["default-selected"] = oldDefault
					groups = slices.Clone(groups)
					groups[i] = updated
					config["proxy-groups"] = groups
				}
			}
			continue
		}
		if first < 0 && len(members) > 0 {
			first = i
		}
	}
	if !included && first >= 0 {
		// The routing source can contain maps shared with the fetch cache.
		updated := maps.Clone(groups[first].(map[string]any))
		members, _ := asAnySlice(updated["proxies"])
		updated["proxies"] = append(slices.Clone(members), name)
		groups = slices.Clone(groups)
		groups[first] = updated
		config["proxy-groups"] = groups
	}
}

// Mihomo sorts automatically included proxies by name. If Sudoku would sort
// first, preserve the former default for a selector without name filters.
func sudokuAutoSelectDefault(group map[string]any, proxies []any, name string) (string, bool) {
	for _, key := range []string{"filter", "exclude-filter"} {
		if value, _ := group[key].(string); value != "" {
			return "", false
		}
	}
	excludedTypes, _ := group["exclude-type"].(string)
	excluded := func(kind string) bool {
		return slices.ContainsFunc(strings.Split(excludedTypes, "|"), func(value string) bool {
			return strings.EqualFold(value, kind)
		})
	}
	if excluded("sudoku") {
		return "", false
	}
	oldDefault := ""
	for _, item := range proxies {
		proxy, _ := item.(map[string]any)
		candidate, _ := proxy["name"].(string)
		kind, _ := proxy["type"].(string)
		if candidate != "" && candidate != name && !excluded(kind) && (oldDefault == "" || candidate < oldDefault) {
			oldDefault = candidate
		}
	}
	if oldDefault > name {
		return oldDefault, true
	}
	return "", true
}

// Decode the fixed wire profile emitted by the independent Sudoku sidecar.
// This does not register Sudoku as an Xray protocol or a generic link parser.
func clashProxyFromSudokuFeed(link, label string) map[string]any {
	token, ok := strings.CutPrefix(strings.TrimSpace(link), "sudoku://")
	if !ok || len(token) > 1024 {
		return nil
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return nil
	}
	var p struct {
		Host   string `json:"h"`
		Port   int    `json:"p"`
		Key    string `json:"k"`
		Table  string `json:"a"`
		AEAD   string `json:"e"`
		Proxy  int    `json:"m"`
		NoMask bool   `json:"hd"`
		Mode   string `json:"hm"`
		TLS    bool   `json:"ht"`
		SNI    string `json:"hh"`
		Path   string `json:"hy"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || p.Table != "entropy" ||
		p.AEAD != "chacha20-poly1305" || p.Proxy != 1080 || len(p.Key) != 128 {
		return nil
	}
	if _, err := hex.DecodeString(p.Key); err != nil {
		return nil
	}
	exactFields := func(names ...string) bool {
		return len(names) == len(fields) && !slices.ContainsFunc(names, func(name string) bool { return fields[name] == nil })
	}
	var httpMask map[string]any
	switch {
	case p.NoMask && exactFields("h", "p", "k", "a", "e", "m", "hd"):
		addr, err := netip.ParseAddr(p.Host)
		if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() || p.Port < 10001 || p.Port > 10030 {
			return nil
		}
		p.Host = addr.String()
		httpMask = map[string]any{"disable": true}
	case p.Mode == "ws" && p.TLS && exactFields("h", "p", "k", "a", "e", "m", "hm", "ht", "hh", "hy"):
		if p.Port != 443 || p.SNI != p.Host || !validSudokuDNSName(p.Host) || !sudokuPathRoot.MatchString(p.Path) {
			return nil
		}
		httpMask = map[string]any{"disable": false, "mode": "ws", "tls": true, "host": p.Host, "path-root": p.Path}
	default:
		return nil
	}
	name := strings.TrimSpace(label)
	if name == "" {
		name = "Sudoku"
	}
	return map[string]any{
		"name": name, "type": "sudoku", "server": p.Host, "port": p.Port,
		"key": p.Key, "aead-method": p.AEAD, "table-type": "prefer_entropy",
		"padding-min": 5, "padding-max": 15, "multiplex": "off",
		"httpmask": httpMask, "enable-pure-downlink": true,
	}
}

func validSudokuDNSName(host string) bool {
	labels := strings.Split(host, ".")
	if len(host) > 253 || len(labels) < 2 {
		return false
	}
	last := labels[len(labels)-1]
	return len(last) > 0 && last[0] >= 'a' && last[0] <= 'z' &&
		!slices.ContainsFunc(labels, func(label string) bool { return !sudokuHostLabel.MatchString(label) })
}
