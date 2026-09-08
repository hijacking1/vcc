package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestShareLinkParsing(t *testing.T) {
	ss := "ss://YWVzLTI1Ni1nY206dGVzdA==@example.com:8388#SS-Test"
	c := parseSS(ss)
	if c == nil || c.Method != "aes-256-gcm" || c.Password != "test" || c.Server != "example.com" || c.Port != 8388 || c.Remarks != "SS-Test" {
		t.Fatalf("ss parse failed: %+v", c)
	}

	vmessJSON := `{"v":"2","ps":"VMess","add":"1.2.3.4","port":443,"id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"auto","net":"ws","tls":"tls","sni":"x.com"}`
	vmess := "vmess://" + b64enc(vmessJSON)
	c = parseVMess(vmess)
	if c == nil || c.UUID != "123e4567-e89b-12d3-a456-426614174000" || c.Server != "1.2.3.4" || c.Port != 443 || c.Network != "ws" || c.TLS != "tls" || c.SNI != "x.com" {
		t.Fatalf("vmess parse failed: %+v", c)
	}

	vless := "vless://123e4567-e89b-12d3-a456-426614174000@1.2.3.4:443?security=reality&sni=yahoo.com&pbk=abc&sid=def&type=grpc&serviceName=gs#VLESS-R"
	c = parseVLESS(vless)
	if c == nil || c.TLS != "reality" || c.RealityPublicKey != "abc" || c.RealityShortID != "def" || c.Network != "grpc" || c.ServiceName != "gs" || c.SNI != "yahoo.com" || c.Remarks != "VLESS-R" {
		t.Fatalf("vless parse failed: %+v", c)
	}

	trojan := "trojan://pass123@5.6.7.8:443?sni=foo.com&type=ws&path=%2Fws#TJ"
	c = parseTrojan(trojan)
	if c == nil || c.Password != "pass123" || c.SNI != "foo.com" || c.Network != "ws" || c.Path != "/ws" || c.TLS != "tls" {
		t.Fatalf("trojan parse failed: %+v", c)
	}

	hy := "hy://8.8.8.8:443?upmbps=100&downmbps=200&auth=secret&obfs=salamander&insecure=1#HY"
	c = parseHysteria(hy)
	if c == nil || c.AuthStr != "secret" || c.UpMbps != 100 || c.DownMbps != 200 || c.Obfs != "salamander" || !c.Insecure {
		t.Fatalf("hysteria parse failed: %+v", c)
	}

	hy2 := "hysteria2://pw@9.9.9.9:8443?sni=x.com&obfs=salamander&obfs-password=op#HY2"
	c = parseHysteria2(hy2)
	if c == nil || c.Password != "pw" || c.SNI != "x.com" || c.Obfs != "salamander" || c.ObfsParam != "op" {
		t.Fatalf("hysteria2 parse failed: %+v", c)
	}

	tuic := "tuic://123e4567-e89b-12d3-a456-426614174000:pw@10.0.0.1:443?congestion_control=bbr&alpn=h3#TUIC"
	c = parseTUIC(tuic)
	if c == nil || c.UUID != "123e4567-e89b-12d3-a456-426614174000" || c.Password != "pw" || c.CongestionCtrl != "bbr" || c.ALPN != "h3" {
		t.Fatalf("tuic parse failed: %+v", c)
	}
}

func TestClashParsing(t *testing.T) {
	body := `proxies:
  - {"type":"vless","name":"VL","server":"1.2.3.4","port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","network":"tcp","flow":"xtls-rprx-vision","servername":"x.com","tls":true,"reality-opts":{"public-key":"pk","short-id":"sid"}}
  - type: ss
    name: SS
    server: 5.6.7.8
    port: 8388
    cipher: aes-128-gcm
    password: pw
  - type: trojan
    name: TJ
    server: 9.9.9.9
    port: 443
    password: secret
    sni: y.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: host.example
`
	nodes := parseClash(body)
	if len(nodes) != 3 {
		t.Fatalf("expected 3 clash nodes, got %d", len(nodes))
	}
	vless := nodes[0]
	if vless.Protocol != ProtocolVLESS || vless.TLS != "reality" || vless.RealityPublicKey != "pk" || vless.Flow != "xtls-rprx-vision" {
		t.Fatalf("clash vless wrong: %+v", vless)
	}
	ss := nodes[1]
	if ss.Protocol != ProtocolShadowsocks || ss.Method != "aes-128-gcm" || ss.Password != "pw" {
		t.Fatalf("clash ss wrong: %+v", ss)
	}
	trojan := nodes[2]
	if trojan.Protocol != ProtocolTrojan || trojan.Password != "secret" || trojan.Path != "/ws" || trojan.Host != "host.example" {
		t.Fatalf("clash trojan wrong: %+v", trojan)
	}
}

func TestSingBoxParsing(t *testing.T) {
	body := `{
  "outbounds": [
    {"type":"vless","tag":"VL","server":"1.2.3.4","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"x.com","reality":{"enabled":true,"public_key":"pk","short_id":"sid"}},"transport":{"type":"grpc","service_name":"gs"}},
    {"type":"shadowsocks","tag":"SS","server":"5.6.7.8","server_port":8388,"method":"aes-128-gcm","password":"pw"},
    {"type":"hysteria2","tag":"HY2","server":"9.9.9.9","server_port":443,"password":"secret","obfs":{"type":"salamander","password":"op"}}
  ]
}`
	nodes := parseSingBox(body)
	if len(nodes) != 3 {
		t.Fatalf("expected 3 singbox nodes, got %d", len(nodes))
	}
	vless := nodes[0]
	if vless.Protocol != ProtocolVLESS || vless.TLS != "reality" || vless.RealityPublicKey != "pk" || vless.ServiceName != "gs" || vless.SNI != "x.com" {
		t.Fatalf("singbox vless wrong: %+v", vless)
	}
	ss := nodes[1]
	if ss.Protocol != ProtocolShadowsocks || ss.Method != "aes-128-gcm" {
		t.Fatalf("singbox ss wrong: %+v", ss)
	}
	hy2 := nodes[2]
	if hy2.Protocol != ProtocolHysteria2 || hy2.Password != "secret" || hy2.Obfs != "salamander" || hy2.ObfsParam != "op" {
		t.Fatalf("singbox hy2 wrong: %+v", hy2)
	}
}

func b64enc(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestCanonicalJSONRoundTrip(t *testing.T) {
	nodes := []ProxyConfig{
		{Protocol: ProtocolShadowsocks, Server: "1.1.1.1", Port: 8388, Method: "aes-128-gcm", Password: "pw", Remarks: "A", Network: "tcp"},
		{Protocol: ProtocolVLESS, Server: "2.2.2.2", Port: 443, UUID: "123e4567-e89b-12d3-a456-426614174000", Network: "ws", TLS: "tls", SNI: "x.com", Path: "/ws", Remarks: "B"},
	}
	dir := t.TempDir()
	if err := writeDeduped(nodes, dir); err != nil {
		t.Fatalf("writeDeduped: %v", err)
	}

	pt := &ProxyTester{}
	loaded, err := pt.LoadCanonicalConfigs(filepath.Join(dir, "deduplicated_urls", "ss.json"), ProtocolShadowsocks)
	if err != nil {
		t.Fatalf("LoadCanonicalConfigs ss: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Method != "aes-128-gcm" || loaded[0].Port != 8388 {
		t.Fatalf("ss round-trip mismatch: %+v", loaded)
	}

	loaded, err = pt.LoadCanonicalConfigs(filepath.Join(dir, "deduplicated_urls", "vless.json"), ProtocolVLESS)
	if err != nil {
		t.Fatalf("LoadCanonicalConfigs vless: %v", err)
	}
	if len(loaded) != 1 || loaded[0].TLS != "tls" || loaded[0].Path != "/ws" {
		t.Fatalf("vless round-trip mismatch: %+v", loaded)
	}
}

func TestReadSubURLsDedup(t *testing.T) {
	content := "" +
		"# 주석 라인\n" +
		"\n" +
		"https://example.com/sub1.txt\n" +
		"  https://example.com/sub2.txt  \n" + // 앞뒤 공백 trim
		"https://example.com/sub1.txt\n" + // 중복
		"https://example.com/sub3.txt\n" +
		"ftp://not.http.example/sub.txt\n" + // http/https 아님 → 제외
		"https://example.com/sub2.txt\n" // 중복
	f := filepath.Join(t.TempDir(), "sub.txt")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	urls, err := readSubURLs(f)
	if err != nil {
		t.Fatalf("readSubURLs: %v", err)
	}

	want := []string{
		"https://example.com/sub1.txt",
		"https://example.com/sub2.txt",
		"https://example.com/sub3.txt",
	}
	if len(urls) != len(want) {
		t.Fatalf("got %d urls, want %d: %v", len(urls), len(want), urls)
	}
	for i, w := range want {
		if urls[i] != w {
			t.Fatalf("url[%d]=%q, want %q", i, urls[i], w)
		}
	}
}

func TestWriteTestSummary(t *testing.T) {
	dir := t.TempDir()
	pt := &ProxyTester{config: &Config{DataDir: dir}}
	pt.initStats()

	pt.updateStats(&TestResultData{Config: ProxyConfig{Protocol: ProtocolShadowsocks}, Result: ResultSuccess})
	pt.updateStats(&TestResultData{Config: ProxyConfig{Protocol: ProtocolShadowsocks}, Result: ResultSuccess})
	pt.updateStats(&TestResultData{Config: ProxyConfig{Protocol: ProtocolShadowsocks}, Result: ResultConnectionError})
	pt.updateStats(&TestResultData{Config: ProxyConfig{Protocol: ProtocolVLESS}, Result: ResultSuccess})

	pt.writeTestSummary()

	data, err := os.ReadFile(filepath.Join(dir, "test_summary.json"))
	if err != nil {
		t.Fatalf("read test_summary.json: %v", err)
	}
	var s struct {
		Total   int64 `json:"total"`
		Success int64 `json:"success"`
		Failed  int64 `json:"failed"`
		Per     map[string]struct {
			Total   int64 `json:"total"`
			Success int64 `json:"success"`
			Failed  int64 `json:"failed"`
		} `json:"per_protocol"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Total != 4 || s.Success != 3 || s.Failed != 1 {
		t.Fatalf("overall mismatch: total=%d success=%d failed=%d", s.Total, s.Success, s.Failed)
	}
	if ss := s.Per["shadowsocks"]; ss.Total != 3 || ss.Success != 2 || ss.Failed != 1 {
		t.Fatalf("shadowsocks mismatch: %+v", ss)
	}
	if vl := s.Per["vless"]; vl.Total != 1 || vl.Success != 1 || vl.Failed != 0 {
		t.Fatalf("vless mismatch: %+v", vl)
	}
}
