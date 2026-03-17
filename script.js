function normalizeLine(line) {
    return String(line || "")
        .replace(/\r/g, "")
        .trim();
}

function setLog(message) {
    const output = document.getElementById("wg-uri");
    if (output) {
        output.innerText = message;
    }
    console.log(message);
}

function parseConfigLine(line) {
    const eqIndex = line.indexOf("=");
    if (eqIndex === -1) {
        return null;
    }

    return {
        key: line.slice(0, eqIndex).trim().toLowerCase(),
        value: line.slice(eqIndex + 1).trim(),
    };
}

function parseEndpoint(endpoint) {
    const value = String(endpoint || "").trim();
    if (!value) {
        return { host: "", port: "" };
    }

    // [ipv6]:port
    let match = value.match(/^\[([^\]]+)\]:(\d+)$/);
    if (match) {
        return { host: match[1], port: match[2] };
    }

    // host:port
    match = value.match(/^(.+):(\d+)$/);
    if (match) {
        return { host: match[1], port: match[2] };
    }

    return { host: value, port: "" };
}

function isIPv4(ip) {
    const match = String(ip || "")
        .trim()
        .match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!match) {
        return false;
    }

    return match.slice(1).every((part) => {
        const n = Number(part);
        return n >= 0 && n <= 255;
    });
}

function isIPv6(ip) {
    const value = String(ip || "").trim();
    return value.includes(":");
}

function extractIPv4FromAddressList(addressValue) {
    const items = String(addressValue || "")
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);

    for (const item of items) {
        const [ip, prefix] = item.split("/").map((v) => (v || "").trim());
        if (isIPv4(ip) && prefix === "32") {
            return `${ip}/32`;
        }
    }

    return "";
}

function extractIPv6FromAddressList(addressValue) {
    const items = String(addressValue || "")
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);

    for (const item of items) {
        const [ip, prefix] = item.split("/").map((v) => (v || "").trim());
        if (isIPv6(ip) && prefix === "128") {
            return `${ip}/128`;
        }
    }

    return "";
}

function isValidInterfaceAddress(value) {
    const trimmed = String(value || "").trim();
    if (!trimmed) {
        return false;
    }

    const [ip, prefix] = trimmed.split("/").map((v) => (v || "").trim());
    if (!ip || !prefix) {
        return false;
    }

    if (isIPv4(ip) && prefix === "32") {
        return true;
    }

    if (isIPv6(ip) && prefix === "128") {
        return true;
    }

    return false;
}

function parseWireGuardConfig(text) {
    const result = {
        name: "WireGuard",
        address: "",
        port: "",
        secretKey: "",
        publicKey: "", // Interface Address (/32 or /128)
        mtu: "",
        peerSecretKey: "",
        peerPublicKey: "",
        allowedIPs: "",
        dns: "",
        keepalive: "",
    };

    const lines = String(text || "").split("\n");
    let section = "";

    for (const rawLine of lines) {
        const line = normalizeLine(rawLine);

        if (!line || line.startsWith("#") || line.startsWith(";")) {
            continue;
        }

        const secMatch = line.match(/^\[(.+?)\]$/);
        if (secMatch) {
            section = secMatch[1].trim().toLowerCase();
            continue;
        }

        const parsed = parseConfigLine(line);
        if (!parsed) {
            continue;
        }

        const { key, value } = parsed;

        if (section === "interface") {
            if (key === "privatekey") result.secretKey = value;
            if (key === "address")
                result.publicKey = extractIPv4FromAddressList(value);
            if (key === "dns") result.dns = value;
            if (key === "mtu") result.mtu = value;
        }

        if (section === "peer") {
            if (key === "publickey") result.peerPublicKey = value;
            if (key === "presharedkey") result.peerSecretKey = value;
            if (key === "allowedips") result.allowedIPs = value;
            if (key === "persistentkeepalive") result.keepalive = value;

            if (key === "endpoint") {
                const endpoint = parseEndpoint(value);
                result.address = endpoint.host;
                result.port = endpoint.port;
            }
        }
    }

    return result;
}

function fillWGForm(data) {
    document.getElementById("name").value = data.name || "WireGuard";
    document.getElementById("address").value = data.address || "";
    document.getElementById("port").value = data.port || "";
    document.getElementById("secretKey").value = data.secretKey || "";
    document.getElementById("publicKey").value = data.publicKey || "";
    document.getElementById("mtu").value = data.mtu || "";
    document.getElementById("peerSecretKey").value = data.peerSecretKey || "";
    document.getElementById("peerPublicKey").value = data.peerPublicKey || "";
    document.getElementById("allowedIPs").value = data.allowedIPs || "";
}

function validateRequiredFields() {
    const requiredFields = [
        { id: "address", label: "Endpoint Host" },
        { id: "port", label: "Endpoint Port" },
        { id: "secretKey", label: "Interface Private Key" },
        { id: "publicKey", label: "Interface Address (/32)" },
        { id: "peerPublicKey", label: "Peer Public Key" },
        { id: "allowedIPs", label: "Allowed IPs" },
    ];

    for (const field of requiredFields) {
        const el = document.getElementById(field.id);
        const value = el ? el.value.trim() : "";
        if (!value) {
            alert(field.label + " is required.");
            if (el) el.focus();
            return false;
        }
    }

    const portEl = document.getElementById("port");
    const port = portEl.value.trim();
    if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
        alert("Endpoint Port must be a valid port number between 1 and 65535.");
        portEl.focus();
        return false;
    }

    const ifaceEl = document.getElementById("publicKey");
    const ifaceAddress = ifaceEl.value.trim();

    if (!isValidInterfaceAddress(ifaceAddress)) {
        alert("Interface Address must be a single IPv4 /32 address.");
        ifaceEl.focus();
        return false;
    }

    const [ip, prefix] = ifaceAddress.split("/");
    if (!(isIPv4(ip) && prefix === "32")) {
        alert("Only IPv4 /32 is used right now. IPv6 is ignored.");
        ifaceEl.focus();
        return false;
    }

    return true;
}

function convertToURL() {
    if (!validateRequiredFields()) {
        return;
    }

    const name = document.getElementById("name").value.trim() || "WireGuard";
    const endpointHost = document.getElementById("address").value.trim();
    const endpointPort = document.getElementById("port").value.trim();
    const secretKey = document.getElementById("secretKey").value.trim();
    const interfaceAddress = document.getElementById("publicKey").value.trim(); // only IPv4/32
    const mtu = document.getElementById("mtu").value.trim();
    const presharedKey = document.getElementById("peerSecretKey").value.trim();
    const peerPublicKey = document.getElementById("peerPublicKey").value.trim();
    const allowedIPs = document.getElementById("allowedIPs").value.trim();

    const params = new URLSearchParams();
    params.set("address", interfaceAddress);
    params.set("publickey", peerPublicKey);
    params.set("allowedips", allowedIPs);
    params.set("keepalive", "25");

    if (mtu) {
        params.set("mtu", mtu);
    }

    if (presharedKey) {
        params.set("presharedkey", presharedKey);
    }

    const url = `wireguard://${encodeURIComponent(secretKey)}@${endpointHost}:${endpointPort}?${params.toString()}#${encodeURIComponent(name)}`;
    document.getElementById("wg-uri").innerText = url;

    console.log("WireGuard parsed interface address:", interfaceAddress);
    console.log("IPv6 interface address is ignored for now.");
}

function copyToClipboard() {
    const urlElement = document.getElementById("wg-uri");
    const text = (urlElement ? urlElement.innerText : "").trim();

    if (!text) {
        alert("Nothing to copy.");
        return;
    }

    navigator.clipboard
        .writeText(text)
        .then(() => {
            alert("Config copied to clipboard!");
        })
        .catch((err) => {
            console.error("Failed to copy:", err);
            alert("Failed to copy to clipboard.");
        });
}

function getFromClipboard() {
    navigator.clipboard
        .readText()
        .then((text) => {
            const raw = String(text || "").trim();

            if (!raw) {
                alert("Clipboard is empty.");
                return;
            }

            const parsed = parseWireGuardConfig(raw);
            fillWGForm(parsed);

            const ipv4Addr = parsed.publicKey || "";
            const ipv6Addr = extractIPv6FromAddressList(
                raw.match(/^\s*Address\s*=(.*)$/im)?.[1] || "",
            );

            if (ipv4Addr) {
                console.log("Using IPv4 interface address:", ipv4Addr);
            } else {
                console.log("No valid IPv4 /32 interface address found.");
            }

            if (ipv6Addr) {
                console.log(
                    "IPv6 interface address found but ignored for now:",
                    ipv6Addr,
                );
            } else {
                console.log("No IPv6 interface address found.");
            }

            setLog("WireGuard config loaded parsed from clipboard");
        })
        .catch((err) => {
            console.error("Failed to read clipboard:", err);
            alert("Failed to read clipboard.");
        });
}

document.addEventListener("paste", (event) => {
    if (!event.target.closest("#wg-form")) getFromClipboard();
});

document.addEventListener("copy", (event) => {
    if (!event.target.closest("#wg-form")) copyToClipboard();
});
