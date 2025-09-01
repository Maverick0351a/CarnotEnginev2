package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	neg "github.com/carnotengine/introspection-loader/negotiated"
)

type hsEvent struct {
Pid      uint32
Tid      uint32
TsNs     uint64
CgroupID uint64
Comm     [16]byte
SslPtr   uint64
Success  int32
Fd       int32
SNI      [256]byte
NidGroup int32
NidCipher int32
}

type ccmObs struct {
	Ts   string `json:"ts"`
	Host string `json:"host"`
	Proc struct {
		Pid  int    `json:"pid"`
		Tid  int    `json:"tid"`
		Name string `json:"name"`
	} `json:"proc"`
	Workload struct {
		CgroupID    string `json:"cgroup_id,omitempty"`
		ContainerID string `json:"container_id,omitempty"`
	} `json:"workload,omitempty"`
	Net struct {
		Fd              int    `json:"fd,omitempty"`
		FdCaptureStatus string `json:"fd_capture_status,omitempty"`
	} `json:"net,omitempty"`
	TLS struct {
		SNI              string `json:"sni"`
		SNIHashed        bool   `json:"sni_hashed,omitempty"`
		CipherSelected   string `json:"cipher_selected,omitempty"`
		GroupSelected    string `json:"group_selected,omitempty"`
		NegotiatedSource string `json:"negotiated_source,omitempty"`
	} `json:"tls"`
}

type bpfObjects struct {
	Events *ebpf.Map `ebpf:"events"`
}

func loadBPF(path string) (*ebpf.CollectionSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(b))
}

func attachUprobe(bin, sym string, prog *ebpf.Program, ret bool) (link.Link, error) {
if ret {
return link.OpenExecutable(bin).Uretprobe(sym, prog, nil)
}
return link.OpenExecutable(bin).Uprobe(sym, prog, nil)
}

func commToString(comm [16]byte) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 { n = len(comm) }
	return string(comm[:n])
}

func cgroupHex(id uint64) string {
	return fmt.Sprintf("0x%x", id)
}

func hashIfNeeded(s string, enabled bool) (string, bool) {
	if !enabled { return s, false }
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:]), true
}

func parseContainerID(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	b, err := os.ReadFile(path)
	if err != nil { return "" }
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines {
		if idx := strings.LastIndex(ln, "/"); idx >= 0 {
			cid := ln[idx+1:]
			if len(cid) > 6 { return cid }
		}
	}
	return ""
}

// Minimal NID mappings; extend as needed.
func nidToCipher(n int) string {
    switch n {
    case 0:
        return ""
    // Common TLS 1.3 ciphers (OpenSSL internal NIDs vary across versions; placeholders):
    case 0x1301: // TLS_AES_128_GCM_SHA256 (iana code)
        return "TLS_AES_128_GCM_SHA256"
    case 0x1302: // TLS_AES_256_GCM_SHA384
        return "TLS_AES_256_GCM_SHA384"
    case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
        return "TLS_CHACHA20_POLY1305_SHA256"
    default:
        return ""
    }
}

func nidToGroup(n int) string {
    switch n {
    case 0:
        return ""
    // Common groups (RFC 8446):
    case 23:
        return "secp256r1"
    case 24:
        return "secp384r1"
    case 29:
        return "x25519"
    case 30:
        return "x448"
    default:
        return ""
    }
}

// sanitizeSNI removes ASCII control characters and truncates to max 255 bytes while preserving UTF-8 boundaries.
func sanitizeSNI(s string) string {
    // filter control runes
    b := make([]rune, 0, len(s))
    for _, r := range s {
        if r < 0x20 || r == 0x7f {
            continue
        }
        b = append(b, r)
    }
    // enforce 255 bytes
    out := make([]byte, 0, 255)
    for _, r := range b {
        rb := []byte(string(r))
        if len(out)+len(rb) > 255 {
            break
        }
        out = append(out, rb...)
    }
    return string(out)
}

// monotonicNsNow returns CLOCK_MONOTONIC nanoseconds
func monotonicNsNow() uint64 {
    var ts unix.Timespec
    if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
        return uint64(time.Now().UnixNano())
    }
    return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// --- HEL allowlist & SPKI pins helpers ---
type pinMap map[string][]byte

func loadAllowlist(path string) map[string]struct{} {
	allow := map[string]struct{}{}
	b, err := os.ReadFile(path)
	if err != nil {
		return allow
	}
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "dns:") {
			h := strings.TrimSpace(strings.TrimPrefix(ln, "dns:"))
			if h != "" {
				allow[h] = struct{}{}
			}
			continue
		}
		if strings.Contains(ln, "://") {
			if u, err := url.Parse(ln); err == nil {
				host := u.Host
				if host != "" {
					allow[host] = struct{}{}
					if h, _, err := net.SplitHostPort(host); err == nil {
						allow[h] = struct{}{}
					}
				}
			}
			continue
		}
		allow[ln] = struct{}{}
	}
	return allow
}

func loadPins(path string) pinMap {
	pins := pinMap{}
	b, err := os.ReadFile(path)
	if err != nil {
		return pins
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) != 2 {
			continue
		}
		host := parts[0]
		pin := parts[1]
		const pref = "sha256/"
		if !strings.HasPrefix(pin, pref) { continue }
		p, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pin, pref))
		if err != nil { continue }
		pins[host] = p
	}
	return pins
}

func hostAllowed(uStr string, allow map[string]struct{}) (string, bool) {
	u, err := url.Parse(uStr)
	if err != nil { return "", false }
	host := u.Host
	hOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil { hOnly = h }
	_, ok1 := allow[host]
	_, ok2 := allow[hOnly]
	return host, ok1 || ok2
}

func clientForHost(host string, pins pinMap) *http.Client {
	// derive hostname without port
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil { hostOnly = h }
	cfg := &tls.Config{}
	if pin, ok := pins[hostOnly]; ok {
		// When pinning, rely solely on SPKI pin; skip default chain validation.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 { return fmt.Errorf("no certs presented") }
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil { return err }
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if !bytes.Equal(sum[:], pin) {
				return fmt.Errorf("spki pin mismatch for %s", hostOnly)
			}
			return nil
		}
	}
	tr := &http.Transport{ TLSClientConfig: cfg }
	return &http.Client{ Timeout: 5 * time.Second, Transport: tr }
}

func postBatch(apiURL string, client *http.Client, o ccmObs) error {
	payload := struct{ Batch []ccmObs `json:"batch"` }{ Batch: []ccmObs{o} }
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(b))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 { return fmt.Errorf("ingest status %s", resp.Status) }
	return nil
}

func main() {
	bpfObj := flag.String("obj", "introspection-engine/ebpf-core/openssl_handshake.bpf.o", "path to BPF object")
	libssl := flag.String("libssl", "/lib/x86_64-linux-gnu/libssl.so.3", "path to libssl to attach uprobes")
	out := flag.String("out", "integrations/runtime/runtime.jsonl", "output JSONL for raw events")
	hashSNI := flag.Bool("hash-sni", false, "hash SNI before emission (privacy)")
	apiURL := flag.String("api-url", "", "if set, POST observations to this /ingest URL (requires HEL allowlist)")
	helList := flag.String("hel-allowlist", "ops/hel_allowlist.txt", "HEL allowlist file")
	spkiPins := flag.String("spki-pins", "ops/spki_pins.txt", "SPKI pins file (optional)")
	negotiatedMode := flag.String("negotiated", "off", "negotiated parameters collection: off|on|strict")
	flag.Parse()

	// HEL allowlist / SPKI pins setup
	allow := loadAllowlist(*helList)
	pins := loadPins(*spkiPins)
	var apiDest string
	var httpClient *http.Client
	if *apiURL != "" {
		if host, ok := hostAllowed(*apiURL, allow); ok {
			apiDest = *apiURL
			httpClient = clientForHost(host, pins)
			log.Printf("[HEL] egress to %s allowed", host)
		} else {
			log.Printf("[HEL] blocked egress to %s (not in allowlist)", *apiURL)
		}
	}

	// Establish wallclock/monotonic base for timestamp translation
	mono0 := monotonicNsNow()
	wall0 := time.Now().UTC()

	// Load BPF object and attach uprobes
	spec, err := loadBPF(*bpfObj)
	if err != nil { log.Fatalf("load bpf: %v", err) }
	coll, err := ebpf.NewCollection(spec)
	if err != nil { log.Fatalf("collection: %v", err) }
	defer coll.Close()

	attach := func(name string) link.Link {
	prog := coll.Programs[name]
	if prog == nil { log.Printf("[warn] program not found: %s", name); return nil }
	is_ret := strings.HasPrefix(name, "uretprobe/")
	sym := strings.TrimPrefix(strings.TrimPrefix(name, "uprobe/"), "uretprobe/")
	l, err := attachUprobe(*libssl, sym, prog, is_ret)
	if err != nil {
	log.Printf("[warn] attach failed %s: %v", name, err)
	return nil
	}
	log.Printf("attached %s", name)
	return l
	}

	links := []link.Link{}
	for name := range coll.Programs {
		if strings.HasPrefix(name, "uprobe/") || strings.HasPrefix(name, "uretprobe/") {
			l := attach(name)
			if l != nil { links = append(links, l) }
		}
	}
	defer func(){ for _, l := range links { _ = l.Close() } }()

	m := coll.Maps["events"]
	if m == nil { log.Fatalf("events map missing") }
	r, err := ringbuf.NewReader(m)
	if err != nil { log.Fatalf("ringbuf reader: %v", err) }
	defer r.Close()

	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil { log.Fatalf("open out: %v", err) }
	defer f.Close()

	host, _ := os.Hostname()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("listening for handshake events… -> %s", *out)
	enc := json.NewEncoder(f)

	for {
		select {
		case <-ctx.Done():
			log.Printf("stopping") ; return
		default:
			rec, err := r.Read()
			if err != nil {
				if err == ringbuf.ErrClosed { return }
				if errno, ok := err.(unix.Errno); ok && errno == unix.EINTR { continue }
				log.Printf("ringbuf read err: %v", err); continue
			}

			var ev hsEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("decode err: %v", err); continue
			}

			sni := string(bytes.TrimRight(ev.SNI[:], "\x00"))
			sni = sanitizeSNI(sni)
			sniVal, sniHashed := hashIfNeeded(sni, *hashSNI)

			obs := ccmObs{}
			// Translate kernel monotonic timestamp to wall clock using loader base
			delta := int64(0)
			if uint64(ev.TsNs) >= mono0 {
				delta = int64(uint64(ev.TsNs) - mono0)
			}
			ts := wall0.Add(time.Duration(delta))
			obs.Ts = ts.UTC().Format(time.RFC3339Nano)
			obs.Host = host
			obs.Proc.Pid = int(ev.Pid)
			obs.Proc.Tid = int(ev.Tid)
			obs.Proc.Name = commToString(ev.Comm)
			obs.Workload.CgroupID = cgroupHex(ev.CgroupID)
			obs.Workload.ContainerID = parseContainerID(ev.Pid)
			if ev.Fd >= 0 {
				obs.Net.Fd = int(ev.Fd)
				obs.Net.FdCaptureStatus = "ok"
			} else {
				obs.Net.FdCaptureStatus = "failed"
			}
			obs.TLS.SNI = sniVal
			obs.TLS.SNIHashed = sniHashed
			// Populate negotiated params
			negErr := false
			cipher := ""
			group := ""
			source := "unknown"
			if *negotiatedMode == "on" || *negotiatedMode == "strict" {
				// best-effort: prefer shim methods
				if ev.SslPtr != 0 {
					if name, err := neg.GetCipherName(uintptr(ev.SslPtr)); err == nil {
						cipher = name
					} else {
						negErr = true
					}
					if g, src := neg.GetGroupSelected(uintptr(ev.SslPtr)); g != "" {
						group = g
						source = src
					} else {
						negErr = true
					}
				}
				if cipher == "" {
					// fallback to BPF CO-RE mapping if available
					cipher = nidToCipher(int(ev.NidCipher))
				}
				if group == "" {
					group = nidToGroup(int(ev.NidGroup))
					if group != "" && source == "unknown" { source = "bpf_core" }
				}
				if *negotiatedMode == "strict" && negErr && cipher == "" && group == "" {
					// emit event but mark warning source
					source = "unknown"
				}
			} else {
				// negotiated collection off: only map from BPF if present
				cipher = nidToCipher(int(ev.NidCipher))
				group = nidToGroup(int(ev.NidGroup))
				if cipher != "" || group != "" { source = "bpf_core" }
			}
			if cipher != "" { obs.TLS.CipherSelected = cipher }
			if group != "" { obs.TLS.GroupSelected = group }
			obs.TLS.NegotiatedSource = source

			line, _ := json.Marshal(obs)
			if _, err := f.Write(append(line, '\n')); err != nil { log.Printf("write: %v", err) }
			// Optional egress to API if enabled and allowed
			if apiDest != "" && httpClient != nil {
				if err := postBatch(apiDest, httpClient, obs); err != nil {
					log.Printf("[HEL] post failed: %v", err)
				}
			}
		}
	}
}
