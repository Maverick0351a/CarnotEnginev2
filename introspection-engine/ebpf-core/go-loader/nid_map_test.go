//go:build linux

package main

import "testing"

func TestNidToGroup(t *testing.T) {
    cases := []struct{ in int; want string }{
        {0, ""},
        {23, "secp256r1"},
        {24, "secp384r1"},
        {29, "x25519"},
        {30, "x448"},
        {9999, ""},
    }
    for _, c := range cases {
        if got := nidToGroup(c.in); got != c.want {
            t.Fatalf("nidToGroup(%d)=%q want %q", c.in, got, c.want)
        }
    }
}

func TestNidToCipher(t *testing.T) {
    cases := []struct{ in int; want string }{
        {0, ""},
        {0x1301, "TLS_AES_128_GCM_SHA256"},
        {0x1302, "TLS_AES_256_GCM_SHA384"},
        {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
        {0x9999, ""},
    }
    for _, c := range cases {
        if got := nidToCipher(c.in); got != c.want {
            t.Fatalf("nidToCipher(%d)=%q want %q", c.in, got, c.want)
        }
    }
}

func TestEventMappingIntegration(t *testing.T) {
    ev := hsEvent{NidGroup: 29, NidCipher: 0x1301}
    if g, c := nidToGroup(int(ev.NidGroup)), nidToCipher(int(ev.NidCipher)); g != "x25519" || c != "TLS_AES_128_GCM_SHA256" {
        t.Fatalf("unexpected mapping group=%q cipher=%q", g, c)
    }
}
