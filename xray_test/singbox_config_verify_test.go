package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

// TestSingBoxGeneratedConfigsValidate feeds a mixed-protocol batch through the
// real config generator and validates the emitted JSON with the sing-box binary.
// This is the guard that would have caught the xray 26.x allowInsecure breakage.
func TestSingBoxGeneratedConfigsValidate(t *testing.T) {
	singbox := findSingBoxExecutable()
	if _, err := exec.LookPath(singbox); err != nil {
		t.Skipf("sing-box not available: %v", err)
	}

	pk := make([]byte, 32)
	pubKey := base64.RawURLEncoding.EncodeToString(pk)

	nodes := []ProxyConfig{
		{Protocol: ProtocolShadowsocks, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pass"},
		{Protocol: ProtocolVMess, Server: "example.com", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Cipher: "auto", AlterID: 0, TLS: "tls", SNI: "example.com", Network: "ws", Path: "/ws", Host: "example.com"},
		{Protocol: ProtocolVLESS, Server: "1.2.3.4", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", TLS: "reality", SNI: "yahoo.com", Flow: "xtls-rprx-vision", RealityPublicKey: pubKey, RealityShortID: "abcd1234", Fingerprint: "chrome"},
		{Protocol: ProtocolTrojan, Server: "example.com", Port: 443, Password: "pass", TLS: "tls", SNI: "example.com"},
		{Protocol: ProtocolHysteria, Server: "1.2.3.4", Port: 36712, AuthStr: "authstr", UpMbps: 100, DownMbps: 100, SNI: "example.com"},
		{Protocol: ProtocolHysteria2, Server: "1.2.3.4", Port: 443, Password: "pass", Obfs: "salamander", ObfsParam: "obfspass", SNI: "example.com"},
		{Protocol: ProtocolTUIC, Server: "1.2.3.4", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Password: "pass", CongestionCtrl: "bbr", SNI: "example.com", ALPN: "h3"},
	}

	ports := make([]int, len(nodes))
	for i := range ports {
		ports[i] = 20000 + i
	}

	sg := NewSingBoxConfigGenerator(singbox)
	cfg, err := sg.GenerateBatchConfig(nodes, ports)
	if err != nil {
		t.Fatalf("GenerateBatchConfig: %v", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tmp, err := os.CreateTemp("", "sb-gen-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	out, err := exec.Command(singbox, "check", "-c", tmp.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check failed: %v\nconfig:\n%s", err, string(data))
	}
	t.Logf("sing-box check OK: %s", string(out))
}
