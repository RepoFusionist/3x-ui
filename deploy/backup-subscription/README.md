# Per-subscription backup node

This sidecar converts one HTTPS Mihomo subscription into an inline entry provider and one authenticated HTTPS backup exit. It listens only on `127.0.0.1:18082` in the 3x-ui network namespace.

In a client's external subscription URL field, enter the local prefix followed immediately by the upstream subscription URL:

```text
http://127.0.0.1:18082/subscription/https://provider.example/path?token=...
```

The upstream may return a Mihomo YAML document with an `自动选择` `url-test` group, or a plain/base64 share-link subscription. Plain links are parsed by the same 3x-ui converter used for external subscription nodes (VMess, VLESS, Trojan, Shadowsocks, Hysteria2, and WireGuard); links that the current Mihomo converter cannot represent are skipped. The sidecar creates one `备用线路-美国` HTTPS exit node, and the 3x-ui Mihomo subscription exposes that exit under the client's existing `专线` selection group (or `PROXY` when no `专线` group exists).

Mount `backend.py` and `chain.py` at `/app/backend.py` and `/app/chain.py` in the sidecar. Keep the existing `/config/config.json` chain exit credentials private; they are not part of this source tree. The legacy `/subscription` endpoint continues to use the configured default source.

The source URL is never written to cache files or logs. The sidecar accepts HTTPS sources that resolve only to public IP addresses and checks HTTPS redirects the same way.


