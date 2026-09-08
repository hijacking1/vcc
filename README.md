# 쿼크 시큐어 VPN 파서

Go 단일 바이너리로 구현된 **프록시 구독 수집·파싱·검증 올인원 파이프라인**.

- 구독 목록(`sub.txt`) → 수집 → share-link / Clash YAML / sing-box JSON 파싱 → 중복 제거 → `data/deduplicated_urls/*.json`
- 각 노드를 실제 sing-box 프로세스로 연결 테스트 → 생존 노드만 `data/working_url/*` 에 프로토콜별 분류 저장
- GitHub Actions (`TestProxy.yml`)가 4시간마다 자동 실행 후 아래 통계를 갱신

---

## 📊 최근 업데이트 현황

<!-- PROXY_STATS_START -->


<!-- PROXY_STATS_END -->

---

## 사용법

```bash
cd xray_test

# 1) 수집 + 파싱 + 중복제거 (sub.txt → data/deduplicated_urls/*.json)
go run . collect

# 2) 실제 연결 테스트 (data/deduplicated_urls → data/working_url/*)
go run . test

# 3) 둘 다
go run . all
```

## 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `SUB_FILE` | `sub.txt` | 구독 URL 목록 파일 (xray_test 기준 상대경로) |
| `PROXY_DATA_DIR` | `../data` | 산출물 디렉터리 |
| `PROXY_COLLECT_WORKERS` | `32` | 수집 동시 worker 수 |
| `PROXY_COLLECT_MAX_BODY_MB` | `8` | 소스 응답 본문 상한 (MB) |
| `PROXY_MAX_WORKERS` | `200` | TCP liveness pre-filter 동시 worker 수 (서버 살았는지/죽었는지 확인) |
| `PROXY_TIMEOUT` | `3` | 노드 연결 타임아웃 (초) |
| `PROXY_TCP_TIMEOUT` | `800` | TCP pre-filter 다이얼 타임아웃 (ms) |
| `PROXY_BATCH_SIZE` | `400` | 테스트 배치 크기 |
| `PROXY_CORE_BATCH` | `25` | sing-box 프로세스 1개당 노드 수 |
| `PROXY_CORE_SLOTS` | `8` | 동시 sing-box 프로세스 수 |
| `SINGBOX_PATH` | (PATH 검색) | sing-box 바이너리 경로 |

## 지원 프로토콜

`Shadowsocks` · `ShadowsocksR` · `VMess` · `VLESS` · `Trojan` · `Hysteria` · `Hysteria2` · `TUIC`

> ⚠️ `ShadowsocksR`은 파싱은 되지만 sing-box 1.6.0+에서 제거되어 **연결 테스트 불가**입니다 (테스트 결과에 "untestable"로 기록).

## 입력 포맷

- share-link (`ss://`, `ssr://`, `vmess://`, `vless://`, `trojan://`, `hysteria://`, `hysteria2://`, `tuic://`)
- Clash YAML (`proxies:` 인라인 JSON 포함)
- sing-box JSON (`outbounds:` 배열)

By. G0513
