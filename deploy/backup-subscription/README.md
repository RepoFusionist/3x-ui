# Dynamic spare subscription

Append `/spare/` and an HTTPS subscription address to an existing 3x-ui subscription URL. A Mihomo request generates one backup node for the current subscriber without saving a subscription record to the database. The original `自动选择` group contains only the subscriber's original nodes; a hidden automatic group tests the imported entry nodes and is used as the dialer for `备用节点`.

The current subscriber's user and inbound routing rule determine the LSP endpoint. The generated backup uses its matching verified HTTPS endpoint and credentials from the private sidecar configuration; generation fails if no unique matching route or verified endpoint exists.

The sidecar accepts a Mihomo YAML subscription with an `自动选择` group or a plain/base64 share-link subscription supported by the 3x-ui Mihomo converter. It listens on `127.0.0.1:18082` in the 3x-ui network namespace. Keep `/config/config.json` and the cache private.

