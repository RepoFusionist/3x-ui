package sub

import (
	"net/http/httptest"
	"testing"
)

func TestSpareSourcePreservesSubscriptionQuery(t *testing.T) {
	for _, path := range []string{
		"https://panel.example/sub/id/spare/https://provider.example/sub?token=a%2Fb&x=1",
		"https://panel.example/sub/id/spare/https%3A%2F%2Fprovider.example%2Fsub%3Ftoken%3Da%252Fb%26x%3D1",
	} {
		got, ok := spareSourceFromRequest(httptest.NewRequest("GET", path, nil))
		if !ok || got != "https://provider.example/sub?token=a%2Fb&x=1" {
			t.Fatalf("unexpected source: %q, ok=%v", got, ok)
		}
	}
}

func TestSpareExitFollowsSubscriberRoute(t *testing.T) {
	const template = `{"routing":{"rules":[{"user":["a"],"inboundTag":["in"],"outboundTag":"socks-a"},{"user":["b"],"inboundTag":["in"],"outboundTag":"socks-b"}]},"outbounds":[{"tag":"socks-a","protocol":"socks","settings":{"servers":[{"address":"lsp.example","port":10001}]}},{"tag":"socks-b","protocol":"socks","settings":{"servers":[{"address":"lsp.example","port":10002}]}},{"tag":"https-a","protocol":"http","settings":{"servers":[{"address":"lsp.example","port":10001}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"lsp.example","allowInsecure":false}}},{"tag":"https-b","protocol":"http","settings":{"servers":[{"address":"lsp.example","port":10002}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"lsp.example","allowInsecure":false}}}]}`
	for _, tc := range []struct {
		email string
		port  int
	}{{"a", 10001}, {"b", 10002}} {
		got, err := resolveSpareExit(template, []spareIdentity{{InboundTag: "in", Email: tc.email}})
		if err != nil || got.Port != tc.port {
			t.Fatalf("email %q: route=%+v err=%v", tc.email, got, err)
		}
	}
}

