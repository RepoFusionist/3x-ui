package sub

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	yaml "github.com/goccy/go-yaml"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestClashSudokuFeedFormatsOnlyItsExactSubscriptionURL(t *testing.T) {
	for _, entry := range []externalLinkEntry{
		{Kind: "link", Value: clashSudokuFeedURL},
		{Kind: "subscription", Value: clashSudokuFeedURL + "?other=1"},
		{Kind: "subscription", Value: "https://example.org/sudoku"},
	} {
		if isClashSudokuFeed(entry) {
			t.Fatal("unmanaged feed unexpectedly opted in")
		}
	}
	if !isClashSudokuFeed(externalLinkEntry{Kind: "subscription", Value: clashSudokuFeedURL}) {
		t.Fatal("configured loopback feed was not selected")
	}
}

func TestClashSudokuFeedNode(t *testing.T) {
	p := map[string]any{
		"h": "192.0.2.1", "p": 10030, "k": strings.Repeat("ab", 64),
		"a": "entropy", "e": "chacha20-poly1305", "m": 1080, "hd": true,
	}
	encode := func() string {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return "sudoku://" + base64.RawURLEncoding.EncodeToString(raw)
	}
	proxy := clashProxyFromSudokuFeed(encode(), "")
	if proxy["type"] != "sudoku" || proxy["name"] != "Sudoku" ||
		proxy["port"] != 10030 || proxy["key"] != p["k"] ||
		proxy["httpmask"].(map[string]any)["disable"] != true ||
		proxy["enable-pure-downlink"] != true {
		t.Fatal("unexpected Mihomo node shape")
	}
	p["x"] = true
	if clashProxyFromSudokuFeed(encode(), "") != nil {
		t.Fatal("unhandled downlink override was accepted")
	}
	delete(p, "x")
	p["h"] = "127.0.0.1"
	if clashProxyFromSudokuFeed(encode(), "") != nil {
		t.Fatal("local destination was accepted")
	}
}

func TestClashSudokuFeedTLSWebSocketNode(t *testing.T) {
	profile := map[string]any{
		"h": "site.example.org", "p": 443, "k": strings.Repeat("ab", 64),
		"a": "entropy", "e": "chacha20-poly1305", "m": 1080,
		"hm": "ws", "ht": true, "hh": "site.example.org", "hy": "sudoku-pilot",
	}
	encode := func() string {
		raw, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		return "sudoku://" + base64.RawURLEncoding.EncodeToString(raw)
	}
	p := clashProxyFromSudokuFeed(encode(), "")
	mask, _ := p["httpmask"].(map[string]any)
	if p["type"] != "sudoku" || p["server"] != "site.example.org" || p["port"] != 443 ||
		mask["mode"] != "ws" || mask["tls"] != true || mask["host"] != "site.example.org" ||
		mask["path-root"] != "sudoku-pilot" || mask["disable"] != false {
		t.Fatal("unexpected WebSocket transport in Mihomo node")
	}
	for _, item := range []struct {
		key   string
		value any
	}{
		{"p", 10030}, {"ht", false}, {"hh", "other.example.org"},
		{"hy", "../wrong"}, {"h", "site.example.org:443"}, {"hm", "legacy"},
	} {
		old := profile[item.key]
		profile[item.key] = item.value
		if clashProxyFromSudokuFeed(encode(), "") != nil {
			t.Fatalf("accepted malformed %s", item.key)
		}
		profile[item.key] = old
	}
}

func TestClashSudokuFeedIsolatedSubscription(t *testing.T) {
	initSubDB(t)
	db := database.GetDB()
	key := strings.Repeat("ab", 64)
	profile, err := json.Marshal(map[string]any{
		"h": "site.example.org", "p": 443, "k": key,
		"a": "entropy", "e": "chacha20-poly1305", "m": 1080,
		"hm": "ws", "ht": true, "hh": "site.example.org", "hy": "sudoku-pilot",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscriptionCache.Lock()
	subscriptionCache.m[clashSudokuFeedURL] = subscriptionCacheEntry{
		links: []string{"sudoku://" + base64.RawURLEncoding.EncodeToString(profile)}, fetchedAt: time.Now(),
	}
	subscriptionCache.Unlock()
	t.Cleanup(func() {
		subscriptionCache.Lock()
		delete(subscriptionCache.m, clashSudokuFeedURL)
		subscriptionCache.Unlock()
	})

	for _, subID := range []string{"with-feed", "with-grant", "without-feed"} {
		client := model.ClientRecord{Email: subID + "@example.org", SubID: subID, Enable: true}
		if err := db.Create(&client).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ClientExternalLink{
			ClientId: client.Id, Kind: model.ExternalLinkKindLink,
			Value: "trojan://test@example.org:443#existing", Remark: "Existing",
		}).Error; err != nil {
			t.Fatal(err)
		}
		if subID == "with-feed" {
			if err := db.Create(&model.ClientExternalLink{
				ClientId: client.Id, Kind: model.ExternalLinkKindSubscription, Value: clashSudokuFeedURL,
				Remark: "Sudoku", SortIndex: 1,
			}).Error; err != nil {
				t.Fatal(err)
			}
		}
		if subID == "with-grant" {
			link := "sudoku://" + base64.RawURLEncoding.EncodeToString(profile)
			if err := db.Create(&model.ClientExternalLink{
				ClientId: client.Id, Kind: model.ExternalLinkKindLink, Value: link,
				Remark: "Sudoku", SortIndex: 1,
			}).Error; err != nil {
				t.Fatal(err)
			}
			if len(expandEntry(externalLinkEntry{Kind: model.ExternalLinkKindLink, Value: link, Remark: "Sudoku"})) != 0 {
				t.Fatal("managed grant leaked into generic external links")
			}
		}
	}

	const routing = `
proxy-groups:
  - name: Manual
    type: select
    proxies: [Existing, DIRECT]
rules: ["MATCH,Manual"]
`
	clash := NewSubClashService(true, routing, false, NewSubService(""))
	for _, tc := range []struct {
		subID        string
		legacy, want bool
	}{{"with-feed", false, true}, {"with-grant", false, true}, {"without-feed", false, false}, {"with-feed", true, false}, {"with-grant", true, false}} {
		var body string
		if tc.legacy {
			body, _, err = clash.GetClashLegacy(tc.subID, "sub.example.org")
		} else {
			body, _, err = clash.GetClash(tc.subID, "sub.example.org")
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "Existing") || strings.Contains(body, key) != tc.want ||
			strings.Contains(body, "type: sudoku") != tc.want || strings.Contains(body, "path-root: sudoku-pilot") != tc.want {
			t.Fatalf("unexpected proxy visibility for subID=%s legacy=%v", tc.subID, tc.legacy)
		}
		if tc.legacy {
			continue
		}
		var cfg struct {
			Groups []struct {
				Name    string   `yaml:"name"`
				Proxies []string `yaml:"proxies"`
			} `yaml:"proxy-groups"`
			Rules []string `yaml:"rules"`
		}
		if err := yaml.Unmarshal([]byte(body), &cfg); err != nil {
			t.Fatal(err)
		}
		wantOrder := "Existing,DIRECT"
		if tc.want {
			wantOrder += ",Sudoku"
		}
		if len(cfg.Groups) != 2 || cfg.Groups[0].Name != "Manual" || cfg.Groups[1].Name != clashAutomaticGroup || strings.Join(cfg.Groups[1].Proxies, ",") != "Existing" ||
			strings.Join(cfg.Groups[0].Proxies, ",") != wantOrder || strings.Join(cfg.Rules, "|") != "MATCH,Manual" {
			t.Fatalf("unexpected selector or routing for subID=%s", tc.subID)
		}
	}
}

func TestClashSudokuFeedPreservesIncludeAllDefault(t *testing.T) {
	group := map[string]any{"name": "Manual", "type": "select", "include-all-proxies": true, "exclude-type": "direct|reject"}
	config := map[string]any{
		"proxies": []map[string]any{
			{"name": "Zurich", "type": "vless"},
			{"name": "Tokyo", "type": "trojan"},
			{"name": "Oslo (direct)", "type": "Direct"},
			{"name": "Sudoku", "type": "sudoku"},
		},
		"proxy-groups": []any{group},
	}
	includeSudokuInClashSelectGroup(config, "Sudoku")
	got := config["proxy-groups"].([]any)[0].(map[string]any)
	if got["default-selected"] != "Tokyo" || got["include-all-proxies"] != true || got["proxies"] != nil || group["default-selected"] != nil {
		t.Fatal("include-all must keep its filter and original default without rewriting the source group")
	}
}
