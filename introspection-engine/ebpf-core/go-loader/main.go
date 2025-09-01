package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
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
	SNI      [128]byte
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

func main() {
	bpfObj := flag.String("obj", "introspection-engine/ebpf-core/openssl_handshake.bpf.o", "path to BPF object")
	libssl := flag.String("libssl", "/lib/x86_64-linux-gnu/libssl.so.3", "path to libssl to attach uprobes")
	out := flag.String("out", "integrations/runtime/runtime.jsonl", "output JSONL for raw events")
	hashSNI := flag.Bool("hash-sni", false, "hash SNI before emission (privacy)")
	flag.Parse()

	// Load BPF object and attach uprobes
	spec, err := loadBPF(*bpfObj)
	if err != nil { log.Fatalf("load bpf: %v", err) }
	coll, err := ebpf.NewCollection(spec)
	if err != nil { log.Fatalf("collection: %v", err) }
	defer coll.Close()

	attach := func(name string) link.Link {
		prog := coll.Programs[name]
		if prog == nil { log.Printf("[warn] program not found: %s", name); return nil }
		ret := strings.HasPrefix(name, "SSL_do_handshake_exit")
		l, err := attachUprobe(*libssl, strings.TrimPrefix(name, "uprobe/"), prog, strings.HasPrefix(name, "uretprobe"))
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
	r, err := perf.NewReader(m, os.Getpagesize()*8)
	if err != nil { log.Fatalf("perf reader: %v", err) }
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
				if perf.IsClosed(err) { return }
				if errno, ok := err.(unix.Errno); ok && errno == unix.EINTR { continue }
				log.Printf("perf read err: %v", err); continue
			}
			if rec.LostSamples > 0 { log.Printf("[drop] lost samples: %d", rec.LostSamples) }

			var ev hsEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("decode err: %v", err); continue
			}

			sni := string(bytes.TrimRight(ev.SNI[:], "\x00"))
			sniVal, sniHashed := hashIfNeeded(sni, *hashSNI)

			obs := ccmObs{}
			obs.Ts = time.Unix(0, int64(ev.TsNs)).UTC().Format(time.RFC3339Nano)
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
			obs.TLS.NegotiatedSource = "unknown"

			line, _ := json.Marshal(obs)
			if _, err := f.Write(append(line, '\n')); err != nil { log.Printf("write: %v", err) }
		}
	}
}
