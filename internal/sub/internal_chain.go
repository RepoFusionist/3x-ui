package sub

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

const internalChainURLPrefix = "http://127.0.0.1:18082/subscription/"
const chainEntryProvider = "101中转节点"
const chainExitProvider = "101出口节点"
const chainAutoGroup = "101自动"
const chainExitName = "备用线路-美国"

var internalChainHTTPClient = &http.Client{
	Timeout:   30 * time.Second,
	Transport: &http.Transport{Proxy: nil},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("internal chain redirects are forbidden")
	},
}

// internalChainCandidate marks every value using the private endpoint prefix,
// including malformed values. Malformed values must not fall through to the
// ordinary subscription fetcher, which would try to fetch loopback as a source.
func isInternalChainCandidate(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), internalChainURLPrefix)
}

func internalChainSource(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, internalChainURLPrefix) {
		return "", false
	}
	source := strings.TrimPrefix(value, internalChainURLPrefix)
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", false
	}
	return source, true
}

func internalChainSubscriptionSource(entries []externalLinkEntry) (string, bool) {
	for _, entry := range entries {
		if !entry.Active || !entry.Enable || entry.Kind != model.ExternalLinkKindSubscription {
			continue
		}
		if source, ok := internalChainSource(entry.Value); ok {
			return source, true
		}
	}
	return "", false
}

func fetchInternalChain(source string) (map[string]any, error) {
	requestURL := internalChainURLPrefix + source
	response, err := internalChainHTTPClient.Get(requestURL)
	if err != nil {
		return nil, errors.New("internal chain fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("internal chain unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, subscriptionMaxBytes+1))
	if err != nil || len(body) > subscriptionMaxBytes {
		return nil, errors.New("internal chain body rejected")
	}
	var doc map[string]any
	if yaml.Unmarshal(body, &doc) != nil {
		return nil, errors.New("internal chain document rejected")
	}
	return doc, nil
}

func chainPayload(doc map[string]any, name string) ([]any, error) {
	providers, _ := doc["proxy-providers"].(map[string]any)
	provider, _ := providers[name].(map[string]any)
	if provider["type"] != "inline" {
		return nil, errors.New("internal chain provider rejected")
	}
	payload, ok := asAnySlice(provider["payload"])
	if !ok || len(payload) == 0 || len(payload) > 512 {
		return nil, errors.New("internal chain payload rejected")
	}
	return payload, nil
}

func mergeInternalChain(base, doc map[string]any, converter *SubClashService) (map[string]any, error) {
	entries, err := chainPayload(doc, chainEntryProvider)
	if err != nil {
		return nil, err
	}
	exits, err := chainPayload(doc, chainExitProvider)
	if err != nil || len(exits) != 1 {
		return nil, errors.New("internal chain requires one exit")
	}
	exit, _ := exits[0].(map[string]any)
	if exit["name"] != chainExitName || exit["type"] != "http" || exit["tls"] != true || exit["skip-cert-verify"] != false || exit["dialer-proxy"] != chainAutoGroup {
		return nil, errors.New("internal chain requires verified HTTPS")
	}
	known := map[string]bool{chainExitName: true, chainAutoGroup: true}
	converted := make([]any, 0, len(entries))
	for index, value := range entries {
		node, _ := value.(map[string]any)
		if rawLink, ok := node["link"].(string); ok {
			name := linkDisplayName(rawLink)
			if name == "" {
				name = fmt.Sprintf("节点-%02d", index+1)
			}
			node = converter.clashProxyFromExternal(rawLink, "101入口 · "+name)
			if node == nil {
				continue
			}
		}
		name, _ := node["name"].(string)
		if !strings.HasPrefix(name, "101入口 · ") || node["dialer-proxy"] != nil {
			return nil, errors.New("internal chain entry rejected")
		}
		if known[name] {
			name = fmt.Sprintf("%s (%d)", name, index+1)
			node["name"] = name
		}
		known[name] = true
		converted = append(converted, node)
	}
	if len(converted) == 0 {
		return nil, errors.New("internal chain has no supported entry nodes")
	}
	var automatic map[string]any
	groups, _ := asAnySlice(doc["proxy-groups"])
	for _, value := range groups {
		group, _ := value.(map[string]any)
		if group["name"] == chainAutoGroup {
			automatic = group
			break
		}
	}
	use, _ := asAnySlice(automatic["use"])
	if automatic["type"] != "url-test" || len(use) != 1 || use[0] != chainEntryProvider || automatic["proxies"] != nil {
		return nil, errors.New("internal chain automatic group rejected")
	}
	// Clone because subscription routing can cache and share its source maps.
	encoded, err := marshalClashYAML(base)
	if err != nil {
		return nil, errors.New("internal chain clone failed")
	}
	var result map[string]any
	if yaml.Unmarshal(encoded, &result) != nil {
		return nil, errors.New("internal chain clone failed")
	}
	native, _ := asAnySlice(result["proxies"])
	for _, value := range native {
		node, _ := value.(map[string]any)
		name, _ := node["name"].(string)
		if known[name] {
			return nil, errors.New("internal chain name collision")
		}
	}
	existing, _ := result["proxy-providers"].(map[string]any)
	if existing == nil {
		existing = map[string]any{}
	}
	if existing[chainEntryProvider] != nil || existing[chainExitProvider] != nil {
		return nil, errors.New("internal chain provider collision")
	}
	providers, _ := doc["proxy-providers"].(map[string]any)
	entryProvider, _ := providers[chainEntryProvider].(map[string]any)
	entryProvider["payload"] = converted
	existing[chainEntryProvider] = entryProvider
	existing[chainExitProvider] = providers[chainExitProvider]
	result["proxy-providers"] = existing
	ownGroups, _ := asAnySlice(result["proxy-groups"])
	var target map[string]any
	for _, value := range ownGroups {
		group, _ := value.(map[string]any)
		if group["name"] == chainAutoGroup {
			return nil, errors.New("internal chain group collision")
		}
		if group["name"] == "专线" {
			target = group
		}
	}
	if target == nil {
		for _, value := range ownGroups {
			group, _ := value.(map[string]any)
			if group["name"] == "PROXY" {
				target = group
				break
			}
		}
	}
	if target == nil || target["type"] != "select" {
		return nil, errors.New("internal chain selection group missing")
	}
	targetUse, _ := asAnySlice(target["use"])
	target["use"] = append(targetUse, chainExitProvider)
	if filter, ok := target["filter"].(string); ok && filter != "" {
		target["filter"] = "(" + filter + ")|^" + chainExitName + "$"
	}
	result["proxy-groups"] = append(ownGroups, automatic)
	return result, nil
}

func applyInternalChain(base map[string]any, source string) map[string]any {
	doc, err := fetchInternalChain(source)
	if err == nil {
		var merged map[string]any
		merged, err = mergeInternalChain(base, doc, &SubClashService{})
		if err == nil {
			return merged
		}
	}
	// Do not log source URLs or node documents; they may contain credentials.
	logger.Warning("Backup subscription unavailable; preserving the client's original Clash subscription")
	return base
}

