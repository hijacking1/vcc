package main

import (
	"net"
	"testing"
)

func TestIsUDPBased(t *testing.T) {
	udp := []ProxyProtocol{ProtocolHysteria, ProtocolHysteria2, ProtocolTUIC}
	tcp := []ProxyProtocol{ProtocolShadowsocks, ProtocolShadowsocksR, ProtocolVMess, ProtocolVLESS, ProtocolTrojan}
	for _, p := range udp {
		if !isUDPBased(p) {
			t.Errorf("expected %s to be UDP-based", p)
		}
	}
	for _, p := range tcp {
		if isUDPBased(p) {
			t.Errorf("expected %s to be TCP-based", p)
		}
	}
}

// TestPreFilterSkipsUDPProtocols guards the regression where the TCP liveness
// pre-filter dialed QUIC (UDP) servers over TCP and rejected every hysteria /
// hysteria2 / tuic node as "unreachable" (collapsing them to 0 working).
func TestPreFilterSkipsUDPProtocols(t *testing.T) {
	// Grab a port that is guaranteed TCP-closed: bind then immediately release.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := l.Addr().(*net.TCPAddr).Port
	l.Close()

	pt := &ProxyTester{config: &Config{MaxWorkers: 4}}

	configs := []ProxyConfig{
		{Protocol: ProtocolHysteria, Server: "127.0.0.1", Port: closedPort},     // UDP-based: must survive pre-filter
		{Protocol: ProtocolShadowsocks, Server: "127.0.0.1", Port: closedPort}, // TCP-based: must be rejected
	}
	results := make([]*TestResultData, len(configs))

	alive := pt.preFilterLive(configs, results, 1)

	if len(alive) != 1 {
		t.Fatalf("expected 1 alive node (UDP skip), got %d", len(alive))
	}
	if alive[0].cfg.Protocol != ProtocolHysteria {
		t.Fatalf("expected hysteria to survive pre-filter, got %s", alive[0].cfg.Protocol)
	}
	if results[0] != nil {
		t.Fatalf("UDP node must not be marked dead, got result: %+v", results[0])
	}
	if results[1] == nil || results[1].Result != ResultConnectionError {
		t.Fatalf("TCP node must be marked dead with connection error, got %+v", results[1])
	}
}
