package main

import "testing"

// TestBuildTransportGRPCServiceNameFallback guards the vmess gRPC bug where the
// serviceName lives in Path (v2rayN format) but buildTransport read only
// ServiceName, silently dropping it and failing the connection.
func TestBuildTransportGRPCServiceNameFallback(t *testing.T) {
	// ServiceName empty, Path holds the serviceName (vmess case).
	c := &ProxyConfig{Network: "grpc", Path: "my-service"}
	tr := buildTransport(c)
	if tr == nil || tr["type"] != "grpc" {
		t.Fatalf("expected grpc transport, got %v", tr)
	}
	if tr["service_name"] != "my-service" {
		t.Fatalf("expected service_name from Path fallback, got %v", tr["service_name"])
	}

	// ServiceName present (vless/Clash/sing-box case) must win.
	c2 := &ProxyConfig{Network: "grpc", ServiceName: "explicit", Path: "ignored"}
	tr2 := buildTransport(c2)
	if tr2["service_name"] != "explicit" {
		t.Fatalf("expected explicit service_name, got %v", tr2["service_name"])
	}
}

// TestBuildTransportHTTPMappings guards http -> h2 and httpupgrade mapping so
// those nodes aren't silently downgraded to raw TCP (which fails the connect).
func TestBuildTransportHTTPMappings(t *testing.T) {
	h2 := buildTransport(&ProxyConfig{Network: "http", Host: "a.com", Path: "/x"})
	if h2 == nil || h2["type"] != "http" {
		t.Fatalf("expected http transport for network=http, got %v", h2)
	}

	up := buildTransport(&ProxyConfig{Network: "httpupgrade", Host: "a.com", Path: "/x"})
	if up == nil || up["type"] != "httpupgrade" {
		t.Fatalf("expected httpupgrade transport, got %v", up)
	}

	// raw/none/tcp must still map to nil (no transport = plain TCP).
	if buildTransport(&ProxyConfig{Network: "tcp"}) != nil {
		t.Fatal("network=tcp must produce nil transport")
	}
	if buildTransport(&ProxyConfig{Network: "none"}) != nil {
		t.Fatal("network=none must produce nil transport")
	}
}
