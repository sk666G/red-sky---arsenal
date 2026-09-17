# Red Sky — Architecture

How the framework fits together.

## Layers

operator -> CLI or browser panel -> Program -> beacon (C++ Windows implant)

## Runtime state (gitignored)

- Data/botnet.sqlite — bots, tasks, events
- Data/panel_auth.json — argon2 hash
- Data/c2_cert.pem + Data/c2_key.pem — TLS
- Data/cve_db.json — offline CVE index

## Beacon check-in

1. Beacon builds CHECKIN message
2. AES-GCM encrypt
3. POST /api/beacon
4. Listener registers bot, pulls tasks
5. Encrypted TASK message back
6. Beacon runs tasks, POST /api/result

## Panel flow

1. Browser loads / static HTML
2. POST /api/login -> argon2 verify -> session cookie
3. /api/bots fleet, /ws live updates
4. Shell tab posts /api/queue
5. Beacon pulls on next poll
6. Result via /api/result

## Where to look

- wire format: Program/c2/protocol.py
- task flow: Program/c2/session.py
- endpoints: Program/c2/listener.py
- builder: Program/botnet/builder.py
- implant: Program/botnet/templates/beacon.cpp
- browser UI: Program/botnet/static/panel.js
