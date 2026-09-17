# Red Sky — OPSEC

What the beacon does to avoid detection, and what it does not. Honest, not marketing.

## What the beacon actually does

- **Indirect syscalls** — resolves NT function SSNs from ntdll and jumps through a clean syscall;ret gadget. Defeats usermode API hooks placed by EDR on ntdll functions.
- **AMSI patch** — overwrites AmsiScanBuffer prologue to return E_INVALIDARG. Only affects PowerShell / .NET scanning in the beacon process.
- **ETW patch** — one-byte ret on EtwEventWrite. Kills the beacon process own telemetry to Windows event tracing.
- **NTDLL unhook** — remaps .text from a fresh copy on disk. Wipes any usermode hooks EDR placed on NT functions.
- **Sleep mask** — XOR-encrypts writable sections of the beacon image during sleep. Defeats naive memory scanners that look for plaintext strings while the beacon is idle.
- **String encryption** — placeholder only in the current build. Not wired up yet.

## What the beacon does not do

- **No kernel driver.** Runs entirely in usermode. Kernel-level EDR (CrowdStrike Falcon, SentinelOne, Defender ATP kernel sensors) sees the beacon regardless of the above.
- **No PPL bypass.** Cannot touch LSASS-protected processes on modern Windows without a driver.
- **No process hollowing.** The beacon runs as itself, not disguised as another process.
- **No signature evasion on disk.** The compiled .exe is unsigned and has not been crypted or packed. AV will fingerprint it.
- **No domain fronting by default.** Self-signed TLS for local mode, real cert for deployed mode. No CDN front.
- **No sandbox check that actually stops execution.** The sandbox.hpp code is available but the beacon does not call it.

## What this means in practice

Against:

| Environment | Beacon survives? |
|---|---|
| Home Windows box, Defender off | yes |
| Home Windows box, Defender on | no, signature hit on disk |
| Small business, standard AV | no, unless crypted |
| Enterprise with usermode EDR | yes for syscall-level, no for memory scans |
| Enterprise with kernel EDR | no |
| Windows with PPL on LSASS | cannot dump LSASS |

## To make it harder to detect

What you would add:

1. Compile-time string encryption (wire string_crypt.py into the builder)
2. Custom packer / crypter for the .exe on disk
3. Real sleep mask using RC4 on all sections, not just writable
4. Sandbox check call at startup, exit silently if hit
5. Signed binary — steal a legit code-signing cert or abuse a leaked one
6. Kernel driver with comms channel — the real upgrade path
7. Domain fronting for the C2 endpoint
8. Malleable profile to blend with real traffic on the target network

None of that is in this build. The beacon is a working implant, not a stealth one.
