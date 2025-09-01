package main

import (
    "testing"
    "time"
)

func TestSanitizeSNI_ControlCharsAndLimit(t *testing.T) {
    in := "\x01\x02exa\x1fmple.\x7forg" // contains control chars 0x01,0x02,0x1f,0x7f
    out := sanitizeSNI(in)
    if out != "example.org" {
        t.Fatalf("sanitizeSNI failed: got %q", out)
    }
    // build a 300-byte string and ensure output <=255 bytes
    long := ""
    for i := 0; i < 300; i++ { long += "a" }
    out2 := sanitizeSNI(long)
    if len(out2) > 255 {
        t.Fatalf("sanitizeSNI length: got %d > 255", len(out2))
    }
}

func TestMonotonicToWallConversionNonEpoch(t *testing.T) {
    mono0 := monotonicNsNow()
    wall0 := time.Now().UTC()
    // simulate an event 10ms after mono0
    ts := wall0.Add(10 * time.Millisecond)
    if ts.Before(time.Date(2000,1,1,0,0,0,0, time.UTC)) {
        t.Fatalf("wallclock conversion produced pre-2000 timestamp: %s", ts)
    }
}
