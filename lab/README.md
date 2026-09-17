# Red Sky — lab

Local vulnerable targets for testing every module. Runs entirely on your Kali box via Docker. Never expose this to the internet.

## Prerequisites

```
sudo apt install docker.io docker-compose-v2 -y
sudo usermod -aG docker $USER   # log out and back in
```

## Start

```
cd lab
./setup.sh up
```

Targets come up on localhost only:

| Target | URL | Purpose |
|--------|-----|---------|
| DVWA| http://127.0.0.1:8081 | classic web vulns |
| Juice Shop | http://127.0.0.1:8082 | modern SPA vulns |
| WebGoat | http://127.0.0.1:8083 | OWASP training |
| Mutillidae | http://127.0.0.1:8084 | broad web sec training |
| vuln-node | http://127.0.0.1:8085 | XSS / SQLi / path traversal |
| redis (unauth) | 127.0.0.1:6379 | unauth redis module |
| mysql (weak) | 127.0.0.1:3307 | weak creds module |

## Stop

```
cd lab
./setup.sh down
```

## Clean

```
docker compose down -v --remove-orphans
docker system prune -f
```

## What to test where

| Module | Target |
|--------|--------|
| redsky recon sweep | 127.0.0.1/32 |
| redsky recon fingerprint | 127.0.0.1 8081-8085 |
| redsky web triage | http://127.0.0.1:8081 |
| redsky web exploit_match | http://127.0.0.1:8082 |
| redsky creds spray | 127.0.0.1:3307 (mysql root:root) |
| redsky c2 serve + beacon | anywhere |

## Warning

Every target in here is deliberately vulnerable. Do not:

-  Change the port bindings from 127.0.0.1 to 0.0.0.0
-  Run this on a VPS with a public IP
-  Use it on a shared network

If you want to test against a remote box, stand up a second Kali VM in a host-only network. Same rules.
