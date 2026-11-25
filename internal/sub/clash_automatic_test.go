package sub

import (
	"reflect"
	"testing"
)

func TestStandaloneClashAutomaticGroup(t *testing.T) {
	nodes := []map[string]any{
		{"name": "Tokyo", "type": "vless", "server": "test.example", "port": 443},
		{"name": "Sydney", "type": "trojan", "server": "test.example", "port": 443},
		{"name": "Sudoku", "type": "sudoku"},
		{"name": chainExitName, "type": "http", "dialer-proxy": chainAutoGroup},
		{"name": "plan information", "type": "socks5", "server": "127.0.0.1", "port": 1080},
	}
	selector := map[string]any{"name": "PROXY", "type": "select", "include-all-proxies": true, "exclude-type": "direct|reject", "default-selected": "Tokyo"}
	profile := map[string]any{"proxies": nodes, "proxy-groups": []map[string]any{selector}, "rules": []string{"MATCH,PROXY"}}
	includeStandaloneClashAutomaticGroup(profile)
	groups, _ := asAnySlice(profile["proxy-groups"])
	got := groups[0].(map[string]any)
	auto := groups[1].(map[string]any)
	if got["default-selected"] != "Tokyo" || !reflect.DeepEqual(got["proxies"], []any{clashAutomaticGroup}) || selector["proxies"] != nil {
		t.Fatal("selector must expose automatic testing and preserve its former default and the template")
	}
	if auto["type"] != "url-test" || auto["use"] != nil || !reflect.DeepEqual(auto["proxies"], []any{"Tokyo", "Sydney"}) {
		t.Fatal("the automatic group must test only existing primary nodes")
	}
	includeStandaloneClashAutomaticGroup(profile)
	if result, _ := asAnySlice(profile["proxy-groups"]); len(result) != 2 {
		t.Fatal("an existing automatic group must stay intact")
	}
}
