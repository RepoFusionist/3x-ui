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
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

const internalChainURLPrefix = "http://127.0.0.1:18082/subscription/"
const chainEntryProvider = "101中转节点"
const chainExitProvider = "101出口节点"
const chainAutoGroup = "101自动"
const chainExitName = "备用节点"
const chainBackendExitName = "备用线路-美国"

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

func mergeInternalChain(base, doc map[string]any, converter *SubClashService, exitRoute spareExitRoute) (map[string]any, error) {
	entries, err := chainPayload(doc, chainEntryProvider)
	if err != nil {
		return nil, err
	}
	exits, err := chainPayload(doc, chainExitProvider)
	if err != nil || len(exits) != 1 {
		return nil, errors.New("internal chain requires one exit")
	}
	exit, _ := exits[0].(map[string]any)
	if exit["name"] != chainBackendExitName || exit["type"] != "http" || exit["tls"] != true || exit["skip-cert-verify"] != false || exit["dialer-proxy"] != chainAutoGroup {
		return nil, errors.New("internal chain requires verified HTTPS")
	}
	server, _ := exit["server"].(string)
	if !strings.EqualFold(server, exitRoute.Server) || exitRoute.Port <= 0 || exitRoute.Port > 65535 {
		return nil, errors.New("internal chain exit does not match the subscriber's LSP")
	}
	exit["name"] = chainExitName
	exit["port"] = exitRoute.Port
	exit["sni"] = exitRoute.SNI
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
	automatic["hidden"] = true
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
	var nativeNames []any
	for _, value := range native {
		node, _ := value.(map[string]any)
		name, _ := node["name"].(string)
		if known[name] {
			return nil, errors.New("internal chain name collision")
		}
		if name != "" && !isDummyProxy(node) {
			nativeNames = append(nativeNames, name)
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
	entryProvider["health-check"] = map[string]any{"enable": true, "url": "https://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000}
	existing[chainEntryProvider] = entryProvider
	existing[chainExitProvider] = providers[chainExitProvider]
	result["proxy-providers"] = existing
	ownGroups, _ := asAnySlice(result["proxy-groups"])
	var autoTarget map[string]any
	var selectorTarget map[string]any
	for _, value := range ownGroups {
		group, _ := value.(map[string]any)
		if group["name"] == chainAutoGroup {
			return nil, errors.New("internal chain group collision")
		}
		if group["name"] == "自动选择" {
			if group["type"] != "url-test" {
				return nil, errors.New("automatic group name collision")
			}
			autoTarget = group
		}
		if group["name"] == "专线" {
			selectorTarget = group
		}
	}
	if selectorTarget == nil {
		for _, value := range ownGroups {
			group, _ := value.(map[string]any)
			if group["name"] == "PROXY" {
				selectorTarget = group
				break
			}
		}
	}
	if selectorTarget == nil || selectorTarget["type"] != "select" {
		return nil, errors.New("internal chain selection group missing")
	}
	// An include-all selector would also expose the internal entry provider.
	if selectorTarget["include-all"] == true {
		selectorTarget["include-all-proxies"] = true
	}
	delete(selectorTarget, "include-all")
	delete(selectorTarget, "include-all-providers")
	if len(nativeNames) > 0 {
		if autoTarget == nil {
			autoTarget = map[string]any{"name": "自动选择", "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300}
			ownGroups = append(ownGroups, autoTarget)
		}
		// Freeze this group to the original nodes so inline providers cannot
		// accidentally add either the backup exit or its internal entry nodes.
		autoTarget["proxies"] = nativeNames
		for _, key := range []string{"use", "include-all", "include-all-proxies", "include-all-providers", "filter", "exclude-filter"} {
			delete(autoTarget, key)
		}
		choices, _ := asAnySlice(selectorTarget["proxies"])
		selectorTarget["proxies"] = append([]any{"自动选择"}, choices...)
	}
	addExitProvider(selectorTarget)
	result["proxy-groups"] = append(ownGroups, automatic)
	return result, nil
}

func addExitProvider(group map[string]any) {
	use, _ := asAnySlice(group["use"])
	found := false
	for _, name := range use {
		if name == chainExitProvider {
			found = true
			break
		}
	}
	if !found {
		group["use"] = append(use, chainExitProvider)
	}
	if filter, ok := group["filter"].(string); ok && filter != "" {
		group["filter"] = "(" + filter + ")|^" + chainExitName + "$"
	}
}

func applyInternalChain(base map[string]any, source string, identities []spareIdentity, settings *service.SettingService) (map[string]any, error) {
	template, err := settings.GetXrayConfigTemplate()
	var exitRoute spareExitRoute
	if err == nil {
		exitRoute, err = resolveSpareExit(template, identities)
	}
	var doc map[string]any
	if err == nil {
		doc, err = fetchInternalChain(source)
	}
	if err == nil {
		var merged map[string]any
		merged, err = mergeInternalChain(base, doc, &SubClashService{}, exitRoute)
		if err == nil {
			return merged, nil
		}
	}
	// Do not log source URLs or node documents; they may contain credentials.
	logger.Warning("Backup subscription unavailable; preserving the client's original Clash subscription")
	return base, err
}

