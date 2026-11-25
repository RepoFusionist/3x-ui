package sub

import (
	"maps"
	"slices"
	"strings"
)

const clashAutomaticGroup = "自动选择"

// The ordinary subscription must be usable without the optional backup chain.
// Use the nodes in this document; never reference the chain's inline providers.
func includeStandaloneClashAutomaticGroup(config map[string]any) {
	proxies, _ := asAnySlice(config["proxies"])
	groups, _ := asAnySlice(config["proxy-groups"])
	names := make([]any, 0, len(proxies))
	for _, value := range proxies {
		p, _ := value.(map[string]any)
		name, _ := p["name"].(string)
		if name == clashAutomaticGroup {
			return
		}
		if name == "" || name == chainExitName || p["dialer-proxy"] != nil || isDummyProxy(p) {
			continue
		}
		kind, _ := p["type"].(string)
		switch strings.ToLower(kind) {
		case "", "direct", "reject", "reject-drop", "pass", "compatible", "sudoku":
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return
	}
	selector := -1
	for i, value := range groups {
		g, _ := value.(map[string]any)
		if g["name"] == clashAutomaticGroup {
			return // Keep an explicitly configured automatic group.
		}
		if g["type"] != "select" {
			continue
		}
		if g["name"] == "专线" || (g["name"] == "PROXY" && selector < 0) {
			selector = i
		}
	}

	groups = slices.Clone(groups)
	if selector >= 0 {
		g := maps.Clone(groups[selector].(map[string]any))
		members, _ := asAnySlice(g["proxies"])
		if !slices.Contains(members, any(clashAutomaticGroup)) {
			// Mihomo puts explicit choices before automatically included nodes.
			// Keep the previous first node as default for the standard template.
			if len(members) == 0 && g["default-selected"] == nil && len(proxies) > 0 &&
				(g["include-all-proxies"] == true || g["include-all"] == true) {
				if previous, known := sudokuAutoSelectDefault(g, proxies, ""); known && previous != "" {
					g["default-selected"] = previous
				}
			}
			g["proxies"] = append(slices.Clone(members), clashAutomaticGroup)
		}
		groups[selector] = g
	}
	config["proxy-groups"] = append(groups, map[string]any{
		"name": clashAutomaticGroup, "type": "url-test", "proxies": names,
		"url": "https://www.gstatic.com/generate_204", "expected-status": 204,
		"interval": 300, "timeout": 5000, "tolerance": 50,
	})
}
