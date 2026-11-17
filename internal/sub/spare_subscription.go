package sub

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/goccy/go-json"
)

type spareIdentity struct {
	InboundTag string
	Email      string
}

type spareExitRoute struct {
	Server string
	Port   int
	SNI    string
}

// The embedded source may be concatenated literally or escaped as one path
// component. The request query belongs to the source in the literal form.
func spareSourceFromRequest(request *http.Request) (string, bool) {
	_, raw, ok := strings.Cut(request.URL.EscapedPath(), "/spare/")
	if !ok || raw == "" || len(raw) > 8192 {
		return "", false
	}
	if !strings.HasPrefix(raw, "https://") {
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			return "", false
		}
		raw = decoded
	}
	// Some reverse proxies collapse the two slashes inside an embedded URL.
	if strings.HasPrefix(raw, "https:/") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + strings.TrimPrefix(raw, "https:/")
	}
	if request.URL.RawQuery != "" {
		separator := "?"
		if strings.Contains(raw, "?") {
			separator = "&"
		}
		raw += separator + request.URL.RawQuery
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", false
	}
	return raw, true
}

func listIncludes(value any, target string) bool {
	items, ok := asAnySlice(value)
	if !ok {
		return false
	}
	for _, item := range items {
		if name, ok := item.(string); ok && name == target {
			return true
		}
	}
	return false
}

// Resolve the user's explicit Xray user+inbound routing rule. A matching,
// certificate-verified HTTPS outbound for the same host and port supplies the
// equivalent LSP endpoint; credentials remain in the private sidecar config.
func resolveSpareExit(template string, identities []spareIdentity) (spareExitRoute, error) {
	var document map[string]any
	if json.Unmarshal([]byte(template), &document) != nil {
		return spareExitRoute{}, errors.New("invalid routing configuration")
	}
	routing, _ := document["routing"].(map[string]any)
	rules, _ := asAnySlice(routing["rules"])
	matchedTag := ""
	for _, identity := range identities {
		for _, value := range rules {
			rule, _ := value.(map[string]any)
			if !listIncludes(rule["user"], identity.Email) {
				continue
			}
			if rule["inboundTag"] != nil && !listIncludes(rule["inboundTag"], identity.InboundTag) {
				continue
			}
			// Destination-specific rules cannot select a single backup exit.
			conditional := false
			for _, key := range []string{"domain", "ip", "source", "sourcePort", "port", "protocol", "attrs", "network"} {
				if rule[key] != nil {
					conditional = true
				}
			}
			if conditional {
				continue
			}
			tag, _ := rule["outboundTag"].(string)
			if tag == "" || (matchedTag != "" && matchedTag != tag) {
				return spareExitRoute{}, errors.New("subscriber has ambiguous LSP routing")
			}
			matchedTag = tag
			break
		}
	}
	if matchedTag == "" {
		return spareExitRoute{}, errors.New("subscriber has no LSP routing rule")
	}
	outbounds, _ := asAnySlice(document["outbounds"])
	var server string
	var port int
	for _, value := range outbounds {
		ob, _ := value.(map[string]any)
		if ob["tag"] != matchedTag || (ob["protocol"] != "socks" && ob["protocol"] != "http") {
			continue
		}
		settings, _ := ob["settings"].(map[string]any)
		servers, _ := asAnySlice(settings["servers"])
		if len(servers) != 1 {
			return spareExitRoute{}, errors.New("subscriber LSP requires one server")
		}
		endpoint, _ := servers[0].(map[string]any)
		server, _ = endpoint["address"].(string)
		port = clashInt(endpoint["port"])
		break
	}
	if server == "" || port <= 0 || port > 65535 {
		return spareExitRoute{}, errors.New("subscriber LSP endpoint unavailable")
	}
	for _, value := range outbounds {
		ob, _ := value.(map[string]any)
		if ob["protocol"] != "http" {
			continue
		}
		settings, _ := ob["settings"].(map[string]any)
		servers, _ := asAnySlice(settings["servers"])
		if len(servers) != 1 {
			continue
		}
		endpoint, _ := servers[0].(map[string]any)
		address, _ := endpoint["address"].(string)
		stream, _ := ob["streamSettings"].(map[string]any)
		tls, _ := stream["tlsSettings"].(map[string]any)
		if !strings.EqualFold(address, server) || clashInt(endpoint["port"]) != port || stream["security"] != "tls" || tls["allowInsecure"] == true {
			continue
		}
		sni, _ := tls["serverName"].(string)
		if sni == "" {
			sni = server
		}
		return spareExitRoute{Server: server, Port: port, SNI: sni}, nil
	}
	return spareExitRoute{}, errors.New("subscriber LSP has no verified HTTPS endpoint")
}

