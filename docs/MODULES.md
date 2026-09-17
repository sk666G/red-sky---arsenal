# Red Sky — Modules

Full catalog. One line per module.

## Recon

- `recon` — host sweep, service fingerprint, subdomain enum, OSINT
- `geoip` — multi-source IP geolocation
- `ipgrab` — IP logger with 302 decoy
- `mail_trace` — email header + SPF/DKIM/DMARC recon
- `social` — OSINT person profile
- `osint_face` — face search + reverse image
- `csint` — breach corpus, leaked docs, paid feeds

## Web

- `web` — fingerprint, CVE match, deface
- `burp_suite` — headless web app scanner
- `fuzzer` — protocol + binary fuzzer
- `proxy_chain` — multi-hop proxy routing

## CCTV / IoT

- `cctv` — discover, default creds, stream, kill
- `firmware` — firmware extraction + analysis
- `ics_scada` — Modbus / DNP3 / BACnet / S7
- `satcom` — satellite / GPS recon

## Credentials

- `creds` — harvest, spray, kerberoast, asrep, dcsync, token
- `ad_attack` — BloodHound, ADCS abuse, delegation attacks
- `cloud_pwn` — AWS / Azure / GCP attack chain

## Payloads

- `payload` — beacon, dropper, persistence, LOLBin, macro, HTA, ISO
- `shellcode` — shellcode generator
- `av_bypass` — crypter, packer, AMSI/ETW patchers
- `evade` — AMSI, ETW, unhook, sandbox detect, anti-debug, string crypt
- `usb` — BadUSB / Rubber Ducky builder

## C2 / Botnet

- `c2` — HTTPS / DNS / ICMP / SMB listener, domain front, malleable
- `botnet` — C2 + tasker + operator panel + beacon builder
- `panel` — browser operator console

## Cracking

- `crack` — classify, patch, keygen, MITM license, toolchain
- `keygen_factory` — automated keygen pipeline

## Wireless / Physical

- `wifi` — recon, handshake capture, PMKID, WPS
- `bluetooth` — BLE scan, service dump, L2CAP recon
- `rfid` — NFC / Mifare / HID read + clone
- `wireless_jam` — RF jamming research (gated)
- `fiber_tap` — optical tap analysis
- `lock_bypass` — physical lock bypass
- `drone` — drone telemetry sniff, MAVLink

## Post-exploitation

- `container_escape` — Docker / K8s escape
- `anti_forensics` — log wipe, prefetch cleanup, MFT timestamps
- `memory_forensics` — live RAM acquisition, process dump
- `vm_detect` — sandbox / VM / hypervisor detection
- `supply_chain` — dependency confusion, typosquat

## Misc

- `ddos` — load-test simulator (50 rps cap, authorized targets only)
- `phish` — phishing framework: clone, catcher, OTP relay, mailer

---

Every module is invoked the same way: `python3 redsky.py <module> [args...]`
