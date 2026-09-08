package main

import (
	"strings"
	"testing"
)

func TestRealityURLReconstruction(t *testing.T) {
	pt := &ProxyTester{}
	rt := float64(0.123)

	cases := []struct {
		name string
		cfg  ProxyConfig
		want []string
	}{
		{
			name: "vless-reality",
			cfg: ProxyConfig{
				Protocol:         ProtocolVLESS,
				Server:           "1.2.3.4",
				Port:             443,
				UUID:             "00000000-0000-0000-0000-000000000000",
				TLS:              "reality",
				SNI:              "example.com",
				Fingerprint:      "chrome",
				Flow:             "xtls-rprx-vision",
				RealityPublicKey: "PUBKEY123",
				RealityShortID:   "abcd1234",
				RealitySpiderX:   "/spx",
			},
			want: []string{"security=reality", "pbk=PUBKEY123", "sid=abcd1234", "spx="},
		},
		{
			name: "trojan-reality",
			cfg: ProxyConfig{
				Protocol:         ProtocolTrojan,
				Server:           "5.6.7.8",
				Port:             443,
				Password:         "pw",
				TLS:              "reality",
				SNI:              "example.org",
				RealityPublicKey: "PBK2",
				RealityShortID:   "ef00",
			},
			want: []string{"security=reality", "pbk=PBK2", "sid=ef00"},
		},
	}

	for _, c := range cases {
		url := pt.createConfigURL(&TestResultData{Config: c.cfg, ResponseTime: &rt, Result: ResultSuccess})
		for _, w := range c.want {
			if !strings.Contains(url, w) {
				t.Errorf("[%s] URL missing %q:\n  got: %s", c.name, w, url)
			}
		}
		t.Logf("[%s] OK -> %s", c.name, url)
	}
}
