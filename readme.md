# WireGuard config converter

Convert a WireGuard `.conf` to a `wireguard://` URL or a sing-box WireGuard endpoint JSON object.

### Use it here

https://sorrtory.github.io/wire2v2ray/

### How to use

Copy a WireGuard config and select **Read from Clipboard**, or enter its fields manually. Choose an output type, then select **Generate Config**.

The sing-box JSON object belongs in the top-level `endpoints` array. Its `tag` comes from **Config Name**. Set **MTU** to `1420` to match the example in the request; when omitted, sing-box uses its default of `1408`. **Domain Resolver** can be set to a DNS server tag such as `bootstrap` if that tag exists in your sing-box configuration. The source config's `DNS` entry is not mapped into the endpoint object.

The URL output can be imported as a WireGuard configuration in clients such as v2rayN or v2rayNG.
