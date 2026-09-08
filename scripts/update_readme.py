#!/usr/bin/env python3
import datetime
import json
import os
import re

START = "<!-- PROXY_STATS_START -->"
END = "<!-- PROXY_STATS_END -->"


def load(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def g(d, key, default=0):
    return d.get(key, default) if d else default


def human_ts(collect, test):
    for d in (collect, test):
        if d and d.get("updated_at"):
            return d["updated_at"].replace("T", " ").replace("Z", " UTC")
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def build_block(collect, test):
    updated = human_ts(collect, test)
    lines = [START, ""]

    lines.append("| 총 URL | 파싱 성공 URL | 파싱 실패 URL | 최종 업데이트 |")
    lines.append("|-------:|-------------:|-------------:|---------------|")
    lines.append(
        "| {total_urls} | {parse_ok} | {parse_fail} | {updated} |".format(
            total_urls=g(collect, "total_urls"),
            parse_ok=g(collect, "parse_success_urls"),
            parse_fail=g(collect, "parse_fail_urls"),
            updated=updated,
        )
    )
    lines.append("")

    lines.append("| 수집된 토탈 VPN | 중복제거 VPN | VPN 성공 | VPN 실패 |")
    lines.append("|---------------:|-------------:|--------:|--------:|")
    lines.append(
        "| {total_nodes} | {dedup_nodes} | {vpn_ok} | {vpn_fail} |".format(
            total_nodes=g(collect, "total_nodes"),
            dedup_nodes=g(collect, "deduped_nodes"),
            vpn_ok=g(test, "success"),
            vpn_fail=g(test, "failed"),
        )
    )

    # Protocol breakdown is derived directly from the latest per_protocol data
    # — no fixed list, so new protocols appear automatically.
    pp = (test or {}).get("per_protocol", {})
    if pp:
        lines.append("")
        lines.append("### 프로토콜별 테스트")
        lines.append("")
        lines.append("| 프로토콜 | 성공 | 실패 |")
        lines.append("|---------|-----:|-----:|")
        for key in sorted(pp.keys()):
            s = pp[key] or {}
            lines.append(
                "| {name} | {ok} | {fail} |".format(
                    name=key,
                    ok=g(s, "success"),
                    fail=g(s, "failed"),
                )
            )

    lines.append("")
    lines.append(END)
    return "\n".join(lines)


def main():
    collect = load("data/collect_summary.json")
    test = load("data/test_summary.json")

    with open("README.md", "r", encoding="utf-8") as f:
        readme = f.read()

    block = build_block(collect, test)
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    if pattern.search(readme):
        readme = pattern.sub(lambda _: block, readme, count=1)
    else:
        readme = readme.rstrip() + "\n\n" + block + "\n"

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme)

    print("README.md updated")


if __name__ == "__main__":
    main()
