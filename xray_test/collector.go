package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Canonical node validation & dedupe (mirrors ProxyTester.isValidConfig /
// getConfigHash, but free-standing so the collector needs no ProxyTester).
// ---------------------------------------------------------------------------

var uuidRegexp = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validNode(c *ProxyConfig) bool {
	if c.Server == "" || c.Port <= 0 || c.Port > 65535 {
		return false
	}
	switch c.Protocol {
	case ProtocolShadowsocks, ProtocolShadowsocksR:
		return c.Method != "" && c.Password != ""
	case ProtocolVMess, ProtocolVLESS:
		return uuidRegexp.MatchString(c.UUID)
	case ProtocolTrojan:
		return c.Password != ""
	case ProtocolHysteria:
		return c.AuthStr != ""
	case ProtocolHysteria2:
		return c.Password != ""
	case ProtocolTUIC:
		return c.UUID != "" && c.Password != ""
	}
	return false
}

func nodeDedupeKey(c *ProxyConfig) string {
	var s string
	switch c.Protocol {
	case ProtocolShadowsocks:
		s = fmt.Sprintf("ss://%s:%d:%s:%s", c.Server, c.Port, c.Method, c.Password)
	case ProtocolShadowsocksR:
		s = fmt.Sprintf("ssr://%s:%d:%s:%s:%s:%s", c.Server, c.Port, c.Method, c.Password, c.Protocol_Param, c.Obfs)
	case ProtocolVMess:
		s = fmt.Sprintf("vmess://%s:%d:%s:%d:%s", c.Server, c.Port, c.UUID, c.AlterID, c.Network)
	case ProtocolVLESS:
		s = fmt.Sprintf("vless://%s:%d:%s:%s:%s", c.Server, c.Port, c.UUID, c.Network, c.RealityPublicKey)
	case ProtocolTrojan:
		s = fmt.Sprintf("trojan://%s:%d:%s:%s", c.Server, c.Port, c.Password, c.Network)
	case ProtocolHysteria:
		s = fmt.Sprintf("hysteria://%s:%d:%s", c.Server, c.Port, c.AuthStr)
	case ProtocolHysteria2:
		s = fmt.Sprintf("hysteria2://%s:%d:%s", c.Server, c.Port, c.Password)
	case ProtocolTUIC:
		s = fmt.Sprintf("tuic://%s:%d:%s:%s", c.Server, c.Port, c.UUID, c.Password)
	}
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Collection driver
// ---------------------------------------------------------------------------

func runCollect() {
	subFile := getEnvOrDefault("SUB_FILE", "sub.txt")
	dataDir := getEnvOrDefault("PROXY_DATA_DIR", "../data")
	workers := getEnvIntOrDefault("PROXY_COLLECT_WORKERS", 32)
	maxBody := int64(getEnvIntOrDefault("PROXY_COLLECT_MAX_BODY_MB", 8)) << 20

	urls, err := readSubURLs(subFile)
	if err != nil {
		log.Fatalf("Failed to read subscription list %s: %v", subFile, err)
	}
	log.Printf("Collector: %d subscription URLs from %s (workers=%d, maxBody=%dMB)", len(urls), subFile, workers, maxBody>>20)

	client := newHTTPClient()

	// Deduplicate incrementally so memory stays bounded by UNIQUE nodes only,
	// not by the raw number of parsed entries across thousands of sources.
	seen := make(map[string]ProxyConfig)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	var parseSuccess, parseFail, totalNodes int64

	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			body, err := fetchURL(client, u, maxBody)
			if err != nil {
				atomic.AddInt64(&parseFail, 1)
				return
			}
			nodes := parseSourceBody(body)
			if len(nodes) == 0 {
				atomic.AddInt64(&parseFail, 1)
				return
			}
			atomic.AddInt64(&parseSuccess, 1)
			atomic.AddInt64(&totalNodes, int64(len(nodes)))
			mu.Lock()
			for _, c := range nodes {
				if !validNode(&c) {
					continue
				}
				k := nodeDedupeKey(&c)
				if _, ok := seen[k]; !ok {
					seen[k] = c
				}
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	all := make([]ProxyConfig, 0, len(seen))
	for _, c := range seen {
		all = append(all, c)
	}
	log.Printf("Collector: parsed %d unique valid nodes across all sources", len(all))

	if err := writeDeduped(all, dataDir); err != nil {
		log.Fatalf("Failed to write deduplicated configs: %v", err)
	}
	log.Printf("Collector: wrote deduplicated_urls/*.json under %s", dataDir)

	// Persist a machine-readable summary consumed by CI to refresh README.
	summary := map[string]interface{}{
		"total_urls":         len(urls),
		"parse_success_urls": atomic.LoadInt64(&parseSuccess),
		"parse_fail_urls":    atomic.LoadInt64(&parseFail),
		"total_nodes":        atomic.LoadInt64(&totalNodes),
		"deduped_nodes":      len(all),
		"updated_at":         time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeSummaryJSON(dataDir, "collect_summary.json", summary); err != nil {
		log.Printf("Collector: failed to write collect_summary.json: %v", err)
	} else {
		log.Printf("Collector: wrote collect_summary.json (parse_ok=%d, parse_fail=%d, total=%d, dedup=%d)",
			summary["parse_success_urls"], summary["parse_fail_urls"], summary["total_nodes"], summary["deduped_nodes"])
	}
}

// writeSummaryJSON marshals v as indented JSON into dataDir/name.
func writeSummaryJSON(dataDir, name string, v interface{}) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, name), data, 0644)
}

func newHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   8 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Force HTTP/1.1: some free subscription servers break HTTP/2 and log
		// "protocol error: received DATA after END_STREAM" noise.
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	return &http.Client{Transport: tr, Timeout: 12 * time.Second}
}

func readSubURLs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var urls []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		urls = append(urls, line)
	}
	return urls, sc.Err()
}

func fetchURL(client *http.Client, u string, maxBody int64) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return maybeBase64Decode(string(data)), nil
	}
	return "", lastErr
}

// ---------------------------------------------------------------------------
// Source-body dispatch: union of share-link / Clash / sing-box parsing.
// ---------------------------------------------------------------------------

func parseSourceBody(body string) []ProxyConfig {
	var out []ProxyConfig

	for _, link := range extractShareLinks(body) {
		if c := parseShareLink(link); c != nil {
			out = append(out, *c)
		}
	}

	if strings.Contains(body, "proxies:") {
		out = append(out, parseClash(body)...)
	}

	if strings.Contains(body, `"outbounds"`) || strings.Contains(body, "outbounds:") {
		out = append(out, parseSingBox(body)...)
	}

	return out
}

var protoFiles = map[ProxyProtocol]string{
	ProtocolShadowsocks:  "ss.json",
	ProtocolShadowsocksR: "ssr.json",
	ProtocolVMess:        "vmess.json",
	ProtocolVLESS:        "vless.json",
	ProtocolTrojan:       "trojan.json",
	ProtocolHysteria:     "hy.json",
	ProtocolHysteria2:    "hysteria2.json",
	ProtocolTUIC:         "tuic.json",
}

func writeDeduped(nodes []ProxyConfig, dataDir string) error {
	dir := filepath.Join(dataDir, "deduplicated_urls")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	groups := make(map[ProxyProtocol][]ProxyConfig)
	for _, c := range nodes {
		groups[c.Protocol] = append(groups[c.Protocol], c)
	}

	order := []ProxyProtocol{
		ProtocolShadowsocks, ProtocolShadowsocksR, ProtocolVMess, ProtocolVLESS,
		ProtocolTrojan, ProtocolHysteria, ProtocolHysteria2, ProtocolTUIC,
	}
	for _, proto := range order {
		list := groups[proto]
		if list == nil {
			list = []ProxyConfig{}
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Server != list[j].Server {
				return list[i].Server < list[j].Server
			}
			return list[i].Port < list[j].Port
		})

		data, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return err
		}
		file := filepath.Join(dir, protoFiles[proto])
		if err := os.WriteFile(file, data, 0644); err != nil {
			return err
		}
		log.Printf("  %-13s: %d nodes -> %s", proto, len(list), filepath.Base(file))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Share-link extraction & parsing
// ---------------------------------------------------------------------------

var shareLinkRe = regexp.MustCompile(`(?i)(ssr|vmess|vless|trojan|hysteria2|hysteria|hy2|hy|tuic|ss)://[^\s"'<>]+`)

func extractShareLinks(text string) []string {
	matches := shareLinkRe.FindAllString(text, -1)
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		m = strings.TrimRight(m, "),;]}|")
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func parseShareLink(link string) *ProxyConfig {
	l := strings.ToLower(link)
	switch {
	case strings.HasPrefix(l, "ssr://"):
		return parseSSR(link)
	case strings.HasPrefix(l, "ss://"):
		return parseSS(link)
	case strings.HasPrefix(l, "vmess://"):
		return parseVMess(link)
	case strings.HasPrefix(l, "vless://"):
		return parseVLESS(link)
	case strings.HasPrefix(l, "trojan://"):
		return parseTrojan(link)
	case strings.HasPrefix(l, "hysteria2://") || strings.HasPrefix(l, "hy2://"):
		return parseHysteria2(link)
	case strings.HasPrefix(l, "hysteria://") || strings.HasPrefix(l, "hy://"):
		return parseHysteria(link)
	case strings.HasPrefix(l, "tuic://"):
		return parseTUIC(link)
	}
	return nil
}

func splitHostPort(addr string) (string, int) {
	if addr == "" {
		return "", 0
	}
	if strings.HasPrefix(addr, "[") {
		if host, p, err := net.SplitHostPort(addr); err == nil {
			return host, atoi(p)
		}
		return strings.Trim(addr, "[]"), 0
	}
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host := addr[:i]
		p := addr[i+1:]
		if n, err := strconv.Atoi(p); err == nil {
			return host, n
		}
		return host, 0
	}
	return addr, 0
}

func urlDecode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func b64Decode(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if d, err := enc.DecodeString(s); err == nil {
			return string(d)
		}
	}
	pad := s
	if m := len(s) % 4; m != 0 {
		pad += strings.Repeat("=", 4-m)
	}
	if d, err := base64.StdEncoding.DecodeString(pad); err == nil {
		return string(d)
	}
	if d, err := base64.URLEncoding.DecodeString(pad); err == nil {
		return string(d)
	}
	return s
}

func tlsFromSecurity(sec string) string {
	switch strings.ToLower(sec) {
	case "tls":
		return "tls"
	case "reality":
		return "reality"
	case "none", "":
		return ""
	}
	return strings.ToLower(sec)
}

func parseSS(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	name := ""
	if i := strings.Index(s, "#"); i >= 0 {
		name = urlDecode(s[i+1:])
		s = s[:i]
	}
	plugin := ""
	if i := strings.Index(s, "?"); i >= 0 {
		q, _ := url.ParseQuery(s[i+1:])
		plugin = q.Get("plugin")
		s = s[:i]
	}

	var method, password, host string
	var port int

	if i := strings.LastIndex(s, "@"); i >= 0 {
		userinfo := s[:i]
		hostport := s[i+1:]
		if u := b64Decode(userinfo); u != userinfo && strings.Contains(u, ":") {
			p := strings.SplitN(u, ":", 2)
			method, password = p[0], p[1]
		} else if strings.Contains(userinfo, ":") {
			p := strings.SplitN(userinfo, ":", 2)
			method, password = p[0], p[1]
		} else {
			method = userinfo
		}
		host, port = splitHostPort(hostport)
	} else {
		d := b64Decode(s)
		if j := strings.LastIndex(d, "@"); j >= 0 {
			u := d[:j]
			if p := strings.SplitN(u, ":", 2); len(p) == 2 {
				method, password = p[0], p[1]
			}
			host, port = splitHostPort(d[j+1:])
		}
	}

	c := &ProxyConfig{
		Protocol: ProtocolShadowsocks,
		Server:   host,
		Port:     port,
		Method:   method,
		Password: password,
		Remarks:  name,
		Network:  "tcp",
	}
	if plugin != "" {
		c.Obfs = plugin
		for _, kv := range strings.Split(plugin, ";") {
			if strings.HasPrefix(kv, "obfs=") {
				c.ObfsParam = strings.TrimPrefix(kv, "obfs=")
			}
		}
	}
	return c
}

func parseSSR(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	var params url.Values
	if i := strings.Index(s, "/"); i >= 0 {
		q := strings.TrimPrefix(s[i+1:], "?")
		params, _ = url.ParseQuery(q)
		s = s[:i]
	}

	d := b64Decode(s)
	parts := strings.SplitN(d, ":", 6)
	if len(parts) < 6 {
		return nil
	}
	host, port := splitHostPort(parts[0] + ":" + parts[1])

	c := &ProxyConfig{
		Protocol:       ProtocolShadowsocksR,
		Server:         host,
		Port:           port,
		Protocol_Param: parts[2],
		Method:         parts[3],
		Obfs:           parts[4],
		Password:       b64Decode(parts[5]),
		Network:        "tcp",
	}
	if params != nil {
		if v := params.Get("remarks"); v != "" {
			c.Remarks = b64Decode(v)
		}
		if v := params.Get("obfsparam"); v != "" {
			c.ObfsParam = b64Decode(v)
		}
		if v := params.Get("protoparam"); v != "" {
			c.Protocol_Param = b64Decode(v)
		}
	}
	return c
}

func parseVMess(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(b64Decode(s)), &m); err != nil {
		return nil
	}

	c := &ProxyConfig{
		Protocol:   ProtocolVMess,
		Server:     asString(m, "add"),
		Port:       asInt(m, "port"),
		UUID:       asString(m, "id"),
		AlterID:    asInt(m, "aid"),
		Cipher:     asString(m, "scy"),
		Network:    asString(m, "net"),
		Path:       asString(m, "path"),
		Host:       asString(m, "host"),
		HeaderType: asString(m, "type"),
		SNI:        asString(m, "sni"),
		Remarks:    asString(m, "ps"),
	}
	if asString(m, "tls") == "tls" {
		c.TLS = "tls"
	}
	if c.Cipher == "" {
		c.Cipher = "auto"
	}
	if c.Network == "" {
		c.Network = "tcp"
	}
	return c
}

func parseVLESS(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	name := ""
	if i := strings.Index(s, "#"); i >= 0 {
		name = urlDecode(s[i+1:])
		s = s[:i]
	}
	at := strings.Index(s, "@")
	if at < 0 {
		return nil
	}
	uuid := s[:at]
	hostport := s[at+1:]

	q := url.Values{}
	host := hostport
	if i := strings.Index(hostport, "?"); i >= 0 {
		host = hostport[:i]
		q, _ = url.ParseQuery(hostport[i+1:])
	}
	h, p := splitHostPort(host)

	c := &ProxyConfig{
		Protocol:         ProtocolVLESS,
		Server:           h,
		Port:             p,
		UUID:             uuid,
		Network:          q.Get("type"),
		TLS:              tlsFromSecurity(q.Get("security")),
		SNI:              q.Get("sni"),
		Path:             q.Get("path"),
		Host:             q.Get("host"),
		Flow:             q.Get("flow"),
		ALPN:             q.Get("alpn"),
		Fingerprint:      q.Get("fp"),
		ServiceName:      q.Get("serviceName"),
		Remarks:          name,
		Encrypt:          "none",
		RealityPublicKey: q.Get("pbk"),
		RealityShortID:   q.Get("sid"),
		RealitySpiderX:   q.Get("spx"),
	}
	if c.Network == "" {
		c.Network = "tcp"
	}
	return c
}

func parseTrojan(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	name := ""
	if i := strings.Index(s, "#"); i >= 0 {
		name = urlDecode(s[i+1:])
		s = s[:i]
	}
	at := strings.Index(s, "@")
	if at < 0 {
		return nil
	}
	password := urlDecode(s[:at])
	hostport := s[at+1:]

	q := url.Values{}
	host := hostport
	if i := strings.Index(hostport, "?"); i >= 0 {
		host = hostport[:i]
		q, _ = url.ParseQuery(hostport[i+1:])
	}
	h, p := splitHostPort(host)

	c := &ProxyConfig{
		Protocol:    ProtocolTrojan,
		Server:      h,
		Port:        p,
		Password:    password,
		Network:     q.Get("type"),
		SNI:         q.Get("sni"),
		Path:        q.Get("path"),
		Host:        q.Get("host"),
		ALPN:        q.Get("alpn"),
		Fingerprint: q.Get("fp"),
		Remarks:     name,
		TLS:         "tls",
	}
	if q.Get("security") == "none" {
		c.TLS = ""
	}
	if c.Network == "" {
		c.Network = "tcp"
	}
	return c
}

func parseHysteria(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	name := ""
	if i := strings.Index(s, "#"); i >= 0 {
		name = urlDecode(s[i+1:])
		s = s[:i]
	}
	auth := ""
	hostport := s
	if i := strings.Index(s, "@"); i >= 0 {
		auth = s[:i]
		hostport = s[i+1:]
	}
	q := url.Values{}
	host := hostport
	if i := strings.Index(hostport, "?"); i >= 0 {
		host = hostport[:i]
		q, _ = url.ParseQuery(hostport[i+1:])
	}
	if auth == "" {
		auth = q.Get("auth")
	}
	h, p := splitHostPort(host)

	c := &ProxyConfig{
		Protocol: ProtocolHysteria,
		Server:   h,
		Port:     p,
		AuthStr:  urlDecode(auth),
		UpMbps:   atoi(firstNonEmpty(q.Get("upmbps"), q.Get("up"))),
		DownMbps: atoi(firstNonEmpty(q.Get("downmbps"), q.Get("down"))),
		Obfs:     q.Get("obfs"),
		SNI:      q.Get("peer"),
		ALPN:     q.Get("alpn"),
		Insecure: q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true"),
		Remarks:  name,
		Network:  "udp",
	}
	if c.SNI == "" {
		c.SNI = h
	}
	return c
}

func parseHysteria2(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	name := ""
	if i := strings.Index(s, "#"); i >= 0 {
		name = urlDecode(s[i+1:])
		s = s[:i]
	}
	auth := ""
	hostport := s
	if i := strings.Index(s, "@"); i >= 0 {
		auth = s[:i]
		hostport = s[i+1:]
	}
	q := url.Values{}
	host := hostport
	if i := strings.Index(hostport, "?"); i >= 0 {
		host = hostport[:i]
		q, _ = url.ParseQuery(hostport[i+1:])
	}
	if auth == "" {
		auth = q.Get("auth")
	}
	h, p := splitHostPort(host)

	c := &ProxyConfig{
		Protocol:  ProtocolHysteria2,
		Server:    h,
		Port:      p,
		Password:  urlDecode(auth),
		Obfs:      q.Get("obfs"),
		ObfsParam: q.Get("obfs-password"),
		SNI:       q.Get("sni"),
		Insecure:  q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true"),
		Remarks:   name,
		Network:   "udp",
	}
	if c.SNI == "" {
		c.SNI = h
	}
	return c
}

func parseTUIC(link string) *ProxyConfig {
	s := link
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	name := ""
	if i := strings.Index(s, "#"); i >= 0 {
		name = urlDecode(s[i+1:])
		s = s[:i]
	}
	at := strings.Index(s, "@")
	if at < 0 {
		return nil
	}
	userinfo := s[:at]
	hostport := s[at+1:]

	uuid, password := userinfo, ""
	if i := strings.Index(userinfo, ":"); i >= 0 {
		uuid, password = userinfo[:i], userinfo[i+1:]
	}

	q := url.Values{}
	host := hostport
	if i := strings.Index(hostport, "?"); i >= 0 {
		host = hostport[:i]
		q, _ = url.ParseQuery(hostport[i+1:])
	}
	h, p := splitHostPort(host)

	return &ProxyConfig{
		Protocol:       ProtocolTUIC,
		Server:         h,
		Port:           p,
		UUID:           uuid,
		Password:       password,
		CongestionCtrl: q.Get("congestion_control"),
		ALPN:           q.Get("alpn"),
		SNI:            q.Get("sni"),
		Insecure:       q.Get("allow_insecure") == "1" || strings.EqualFold(q.Get("allow_insecure"), "true"),
		Remarks:        name,
		Network:        "udp",
	}
}

// ---------------------------------------------------------------------------
// Clash YAML parser
// ---------------------------------------------------------------------------

func parseClash(body string) []ProxyConfig {
	var root map[string]interface{}
	if err := yaml.Unmarshal([]byte(body), &root); err != nil {
		return nil
	}
	proxies, ok := root["proxies"]
	if !ok {
		return nil
	}
	arr, ok := proxies.([]interface{})
	if !ok {
		return nil
	}
	var out []ProxyConfig
	for _, item := range arr {
		if c := clashProxyToNode(item); c != nil {
			out = append(out, *c)
		}
	}
	return out
}

func clashProxyToNode(raw interface{}) *ProxyConfig {
	var m map[string]interface{}
	switch v := raw.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil
		}
	case map[string]interface{}:
		m = v
	case map[interface{}]interface{}:
		m = yamlMapToStringMap(v)
	default:
		return nil
	}
	return clashNodeFromMap(m)
}

func clashNodeFromMap(m map[string]interface{}) *ProxyConfig {
	typ := asString(m, "type")
	server := asString(m, "server")
	port := asInt(m, "port")
	if server == "" || port == 0 {
		return nil
	}
	c := &ProxyConfig{Server: server, Port: port, Remarks: asString(m, "name")}

	switch typ {
	case "ss":
		c.Protocol = ProtocolShadowsocks
		c.Method = asString(m, "cipher")
		c.Password = asString(m, "password")
		c.Network = "tcp"
		if p := asString(m, "plugin"); p != "" {
			c.Obfs = p
			c.ObfsParam = asString(m, "plugin-opts")
		}
	case "ssr":
		c.Protocol = ProtocolShadowsocksR
		c.Method = asString(m, "cipher")
		c.Password = asString(m, "password")
		c.Protocol_Param = asString(m, "protocol-param")
		c.Obfs = asString(m, "obfs")
		c.ObfsParam = asString(m, "obfs-param")
		c.Network = "tcp"
	case "vmess":
		c.Protocol = ProtocolVMess
		c.UUID = asString(m, "uuid")
		c.AlterID = asInt(m, "alterId")
		c.Cipher = asString(m, "cipher")
		c.Network = clashNetwork(asString(m, "network"))
		c.Path = wsPath(m)
		c.Host = wsHost(m)
		c.SNI = asString(m, "servername")
		c.TLS = tlsFromBool(asBool(m, "tls"))
		c.Fingerprint = asString(m, "client-fingerprint")
		c.ALPN = joinList(m, "alpn")
		if c.Cipher == "" {
			c.Cipher = "auto"
		}
	case "vless":
		c.Protocol = ProtocolVLESS
		c.UUID = asString(m, "uuid")
		c.Flow = asString(m, "flow")
		c.Encrypt = "none"
		c.Network = clashNetwork(asString(m, "network"))
		c.Path = wsPath(m)
		c.Host = wsHost(m)
		c.SNI = asString(m, "servername")
		c.TLS = clashTLSType(m)
		c.Fingerprint = asString(m, "client-fingerprint")
		c.ALPN = joinList(m, "alpn")
		if ro := asMap(m, "reality-opts"); ro != nil {
			c.RealityPublicKey = asString(ro, "public-key")
			c.RealityShortID = asString(ro, "short-id")
		}
		if go_ := asMap(m, "grpc-opts"); go_ != nil {
			c.ServiceName = asString(go_, "grpc-service-name")
		}
	case "trojan":
		c.Protocol = ProtocolTrojan
		c.Password = asString(m, "password")
		c.Network = clashNetwork(asString(m, "network"))
		c.SNI = asString(m, "sni")
		if c.SNI == "" {
			c.SNI = asString(m, "servername")
		}
		c.Path = wsPath(m)
		c.Host = wsHost(m)
		c.TLS = "tls"
		c.Fingerprint = asString(m, "client-fingerprint")
		c.ALPN = joinList(m, "alpn")
		c.Insecure = asBool(m, "skip-cert-verify")
	case "hysteria":
		c.Protocol = ProtocolHysteria
		c.AuthStr = asString(m, "auth")
		if c.AuthStr == "" {
			c.AuthStr = asString(m, "auth-str")
		}
		c.UpMbps = asInt(m, "up")
		c.DownMbps = asInt(m, "down")
		c.Obfs, c.ObfsParam = obfsTypeAndParam(m)
		c.SNI = asString(m, "sni")
		if c.SNI == "" {
			c.SNI = server
		}
		c.ALPN = joinList(m, "alpn")
		c.Insecure = asBool(m, "skip-cert-verify")
		c.Network = "udp"
	case "hysteria2":
		c.Protocol = ProtocolHysteria2
		c.Password = asString(m, "password")
		if c.Password == "" {
			c.Password = asString(m, "auth")
		}
		c.Obfs, c.ObfsParam = obfsTypeAndParam(m)
		c.SNI = asString(m, "sni")
		if c.SNI == "" {
			c.SNI = server
		}
		c.ALPN = joinList(m, "alpn")
		c.Insecure = asBool(m, "skip-cert-verify")
		c.Network = "udp"
	case "tuic":
		c.Protocol = ProtocolTUIC
		c.UUID = asString(m, "uuid")
		c.Password = asString(m, "password")
		c.CongestionCtrl = asString(m, "congestion-controller")
		c.SNI = asString(m, "sni")
		c.ALPN = joinList(m, "alpn")
		c.Insecure = asBool(m, "skip-cert-verify")
		c.Network = "udp"
	default:
		return nil
	}
	return c
}

// ---------------------------------------------------------------------------
// sing-box JSON parser
// ---------------------------------------------------------------------------

func parseSingBox(body string) []ProxyConfig {
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		return nil
	}
	outbounds, ok := root["outbounds"].([]interface{})
	if !ok {
		return nil
	}
	var out []ProxyConfig
	for _, item := range outbounds {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if c := singboxNodeFromMap(m); c != nil {
			out = append(out, *c)
		}
	}
	return out
}

func singboxNodeFromMap(m map[string]interface{}) *ProxyConfig {
	typ := asString(m, "type")
	server := asString(m, "server")
	port := asInt(m, "server_port")
	if server == "" || port == 0 {
		return nil
	}
	c := &ProxyConfig{Server: server, Port: port, Remarks: asString(m, "tag")}

	transport := asMap(m, "transport")
	tlsM := asMap(m, "tls")

	switch typ {
	case "shadowsocks":
		c.Protocol = ProtocolShadowsocks
		c.Method = asString(m, "method")
		c.Password = asString(m, "password")
		c.Network = "tcp"
		if p := asString(m, "plugin"); p != "" {
			c.Obfs = p
		}
	case "shadowsocksr":
		c.Protocol = ProtocolShadowsocksR
		c.Method = asString(m, "method")
		c.Password = asString(m, "password")
		c.Protocol_Param = asString(m, "protocol")
		c.Obfs = asString(m, "obfs")
		c.ObfsParam = asString(m, "obfs_param")
		c.Network = "tcp"
	case "vmess":
		c.Protocol = ProtocolVMess
		c.UUID = asString(m, "uuid")
		c.AlterID = asInt(m, "alter_id")
		c.Cipher = asString(m, "security")
		c.Network = singboxNetwork(transportType(transport))
		c.Path = transportPath(transport)
		c.Host = transportHost(transport)
		c.TLS = tlsFromMap(tlsM)
		c.SNI = tlsSNI(tlsM)
		c.ALPN = tlsALPN(tlsM)
		c.Fingerprint = tlsFingerprint(tlsM)
		if c.Cipher == "" {
			c.Cipher = "auto"
		}
	case "vless":
		c.Protocol = ProtocolVLESS
		c.UUID = asString(m, "uuid")
		c.Flow = asString(m, "flow")
		c.Encrypt = "none"
		c.Network = singboxNetwork(transportType(transport))
		c.Path = transportPath(transport)
		c.Host = transportHost(transport)
		c.ServiceName = transportServiceName(transport)
		c.TLS = tlsFromMap(tlsM)
		c.SNI = tlsSNI(tlsM)
		c.ALPN = tlsALPN(tlsM)
		c.Fingerprint = tlsFingerprint(tlsM)
		if c.TLS == "reality" {
			if r := asMap(tlsM, "reality"); r != nil {
				c.RealityPublicKey = asString(r, "public_key")
				c.RealityShortID = asString(r, "short_id")
			}
		}
	case "trojan":
		c.Protocol = ProtocolTrojan
		c.Password = asString(m, "password")
		c.Network = singboxNetwork(transportType(transport))
		c.Path = transportPath(transport)
		c.Host = transportHost(transport)
		c.TLS = "tls"
		c.SNI = tlsSNI(tlsM)
		c.ALPN = tlsALPN(tlsM)
		c.Fingerprint = tlsFingerprint(tlsM)
	case "hysteria":
		c.Protocol = ProtocolHysteria
		c.AuthStr = asString(m, "auth_str")
		c.UpMbps = asInt(m, "up_mbps")
		c.DownMbps = asInt(m, "down_mbps")
		c.Obfs, c.ObfsParam = obfsTypeAndParam(m)
		c.SNI = tlsSNI(tlsM)
		if c.SNI == "" {
			c.SNI = server
		}
		c.ALPN = tlsALPN(tlsM)
		c.Network = "udp"
	case "hysteria2":
		c.Protocol = ProtocolHysteria2
		c.Password = asString(m, "password")
		c.Obfs, c.ObfsParam = obfsTypeAndParam(m)
		c.SNI = tlsSNI(tlsM)
		if c.SNI == "" {
			c.SNI = server
		}
		c.ALPN = tlsALPN(tlsM)
		c.Network = "udp"
	case "tuic":
		c.Protocol = ProtocolTUIC
		c.UUID = asString(m, "uuid")
		c.Password = asString(m, "password")
		c.CongestionCtrl = asString(m, "congestion_control")
		c.SNI = tlsSNI(tlsM)
		c.ALPN = tlsALPN(tlsM)
		c.Network = "udp"
	default:
		return nil
	}
	return c
}

// ---------------------------------------------------------------------------
// Generic map / field helpers
// ---------------------------------------------------------------------------

func asString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return ""
}

func asInt(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		return atoi(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	}
	return 0
}

func asBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, _ := strconv.ParseBool(t)
		return b
	case int:
		return t != 0
	}
	return false
}

func asMap(m map[string]interface{}, key string) map[string]interface{} {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case map[string]interface{}:
		return t
	case map[interface{}]interface{}:
		return yamlMapToStringMap(t)
	}
	return nil
}

func yamlMapToStringMap(m map[interface{}]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[fmt.Sprint(k)] = v
	}
	return out
}

func joinList(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []string:
		return strings.Join(t, ",")
	case []interface{}:
		var parts []string
		for _, x := range t {
			parts = append(parts, fmt.Sprint(x))
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func obfsTypeAndParam(m map[string]interface{}) (string, string) {
	v, ok := m["obfs"]
	if !ok || v == nil {
		return "", ""
	}
	switch t := v.(type) {
	case string:
		return t, asString(m, "obfs-password")
	case map[string]interface{}:
		return asString(t, "type"), asString(t, "password")
	}
	return "", ""
}

// --- Clash-specific helpers ---

func clashNetwork(n string) string {
	switch strings.ToLower(n) {
	case "ws":
		return "ws"
	case "h2":
		return "h2"
	case "grpc":
		return "grpc"
	case "http":
		return "http"
	case "tcp", "":
		return "tcp"
	}
	return strings.ToLower(n)
}

func wsPath(m map[string]interface{}) string {
	if o := asMap(m, "ws-opts"); o != nil {
		if p := asString(o, "path"); p != "" {
			return p
		}
	}
	return asString(m, "ws-path")
}

func wsHost(m map[string]interface{}) string {
	if o := asMap(m, "ws-opts"); o != nil {
		if hdr := asMap(o, "headers"); hdr != nil {
			if h := asString(hdr, "Host"); h != "" {
				return h
			}
		}
	}
	return asString(m, "ws-header-host")
}

func tlsFromBool(b bool) string {
	if b {
		return "tls"
	}
	return ""
}

func clashTLSType(m map[string]interface{}) string {
	if ro := asMap(m, "reality-opts"); ro != nil {
		if asString(ro, "public-key") != "" {
			return "reality"
		}
	}
	if asBool(m, "tls") {
		return "tls"
	}
	return ""
}

// --- sing-box-specific helpers ---

func transportType(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	return asString(t, "type")
}

func transportPath(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	return asString(t, "path")
}

func transportHost(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	if hdr := asMap(t, "headers"); hdr != nil {
		if h := asString(hdr, "Host"); h != "" {
			return h
		}
	}
	return asString(t, "host")
}

func transportServiceName(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	return asString(t, "service_name")
}

func singboxNetwork(n string) string {
	switch strings.ToLower(n) {
	case "ws":
		return "ws"
	case "h2", "http":
		return "h2"
	case "grpc":
		return "grpc"
	case "quic":
		return "quic"
	case "tcp", "":
		return "tcp"
	}
	return strings.ToLower(n)
}

func tlsFromMap(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	if r := asMap(t, "reality"); r != nil && asBool(r, "enabled") {
		return "reality"
	}
	if asBool(t, "enabled") {
		return "tls"
	}
	return ""
}

func tlsSNI(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	return asString(t, "server_name")
}

func tlsALPN(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	return joinList(t, "alpn")
}

func tlsFingerprint(t map[string]interface{}) string {
	if t == nil {
		return ""
	}
	if u := asMap(t, "utls"); u != nil {
		return asString(u, "fingerprint")
	}
	return ""
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func looksBase64(s string) bool {
	if len(s) < 16 {
		return false
	}
	clean := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', ' ', '\t':
			return -1
		}
		return r
	}, s)
	if clean == "" {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return true
	}
	_, err := base64.URLEncoding.DecodeString(clean)
	return err == nil
}

func maybeBase64Decode(s string) string {
	t := strings.TrimSpace(s)
	for i := 0; i < 2; i++ {
		if !looksBase64(t) {
			break
		}
		d := b64Decode(t)
		if d == "" || d == t {
			break
		}
		t = strings.TrimSpace(d)
	}
	return t
}
