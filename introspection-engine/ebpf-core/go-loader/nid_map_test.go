package main

import "testing"

func TestNidToGroup(t *testing.T) {
	cases := map[int]string{
		0:   "",
		23:  "secp256r1",
		24:  "secp384r1",
		29:  "x25519",
		30:  "x448",
		999: "",
	}
	for in, want := range cases {
		if got := nidToGroup(in); got != want {
			t.Errorf("nidToGroup(%d)=%q want %q", in, got, want)
		}
	}
}

func TestNidToCipher(t *testing.T) {
	cases := map[int]string{
		0:       "",
		0x1301:  "TLS_AES_128_GCM_SHA256",
		0x1302:  "TLS_AES_256_GCM_SHA384",
		0x1303:  "TLS_CHACHA20_POLY1305_SHA256",
		0x9999:  "",
	}
	for in, want := range cases {
		if got := nidToCipher(in); got != want {
			t.Errorf("nidToCipher(%d)=%q want %q", in, got, want)
		}
	}
}
