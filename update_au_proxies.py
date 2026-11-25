import concurrent.futures
import json
import re
import time
import requests
import yaml
from bs4 import BeautifulSoup

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
BASE_URL = "https://www.freeproxy.world/?type=&anonymity=&country=AU&speed=&port=&page={page}"

ISP_KEYWORDS = (
    "aussie", "telstra", "optus", "tpg", "vocus", "internode", "iinet",
    "superloop", "aussie fibre", "dicker", "intervolve", "aapt", "vodafone"
)


def fetch_freeproxy_pages(max_pages=5):
    proxies = []
    seen = set()
    for page in range(1, max_pages + 1):
        try:
            resp = requests.get(BASE_URL.format(page=page), headers={"User-Agent": UA}, timeout=15)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            table = soup.find("table")
            if not table:
                continue
            for tr in table.find_all("tr"):
                cols = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
                if len(cols) >= 8:
                    ip, port, country, city, speed, ptype, anon, last_check = cols[:8]
                    ptype = ptype.lower().strip()
                    if ptype == "http https":
                        ptype = "https"
                    if ptype not in ("http", "https", "socks5"):
                        continue
                    if not ip or not port.isdigit():
                        continue
                    key = (ip, int(port), ptype)
                    if key not in seen:
                        seen.add(key)
                        proxies.append({
                            "ip": ip,
                            "port": int(port),
                            "city": city,
                            "listed_speed": speed,
                            "type": ptype,
                            "anonymity": anon,
                            "last_check": last_check,
                        })
        except Exception as e:
            print(f"Page {page} fetch error: {e}")
    return proxies


def test_connectivity(proxy):
    ptype = proxy["type"]
    ip = proxy["ip"]
    port = proxy["port"]
    scheme = "socks5h" if ptype == "socks5" else ptype
    proxy_url = f"{scheme}://{ip}:{port}"
    proxies_cfg = {"http": proxy_url, "https": proxy_url}
    start = time.time()
    try:
        r = requests.get(
            "https://ipinfo.io/json",
            proxies=proxies_cfg,
            timeout=6,
            headers={"User-Agent": UA},
        )
        latency_ms = int((time.time() - start) * 1000)
        if r.status_code == 200:
            data = r.json()
            if data.get("country") == "AU":
                return {**proxy, "alive": True, "latency_ms": latency_ms}
    except Exception:
        pass
    return {**proxy, "alive": False, "latency_ms": 99999}


def check_ip_quality(ip):
    ipinfo = {}
    scam = {"score": 50, "datacenter": "Unknown", "blacklists": 0}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            ipinfo = r.json()
    except Exception:
        pass

    try:
        r = requests.get(f"https://scamalytics.com/ip/{ip}", headers={"User-Agent": UA}, timeout=12)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            m = re.search(r"Fraud Score:\s*(\d+)", soup.get_text(" ", strip=True))
            score = int(m.group(1)) if m else 50
            fields = {}
            for tr in soup.select("table tr"):
                cols = [c.get_text(" ", strip=True) for c in tr.find_all(["th", "td"])]
                if len(cols) >= 2:
                    fields[cols[0]] = cols[1]
            bl = sum(
                1 for k, v in fields.items()
                if v == "Yes" and k not in (
                    "Datacenter", "Public Proxy", "Anonymizing VPN",
                    "Tor Exit Node", "Web Proxy", "Search Engine Robot"
                )
            )
            scam = {
                "score": score,
                "datacenter": fields.get("Datacenter", "Unknown"),
                "blacklists": bl,
            }
    except Exception:
        pass

    return ipinfo, scam


def build_clash_yaml(selected):
    proxies = []
    names = []
    for idx, item in enumerate(selected, 1):
        org_short = re.sub(r"[^A-Za-z0-9]+", "", item.get("org_name", "AU"))[:14] or "AU"
        proto_tag = item["type"].upper()
        name = f"AU-{idx:02d}-{org_short}-{proto_tag}"
        names.append(name)
        node = {
            "name": name,
            "type": "socks5" if item["type"] == "socks5" else "http",
            "server": item["ip"],
            "port": item["port"],
        }
        if item["type"] == "https":
            node["tls"] = True
            node["skip-cert-verify"] = True
        proxies.append(node)

    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AU-Select",
                "type": "select",
                "proxies": ["AU-Auto"] + names + ["DIRECT"],
            },
            {
                "name": "AU-Auto",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": names,
            },
        ],
        "rules": ["MATCH,AU-Select"],
    }
    return yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True)


def main():
    raw = fetch_freeproxy_pages(5)
    print(f"Fetched {len(raw)} proxies from FreeProxy.World")
    if not raw:
        raise RuntimeError("No proxies fetched; keeping existing file.")

    # Prioritize diverse IPs and High anonymity / HTTPS / SOCKS5 for connectivity check
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        tested = list(ex.map(test_connectivity, raw))

    alive = [p for p in tested if p["alive"]]
    print(f"Live AU proxies verified: {len(alive)}")

    # Fallback if runner network blocks some ports: use top diverse candidates
    pool = alive if len(alive) >= 10 else raw

    # Deduplicate by IP (keep best protocol/latency per IP)
    best_by_ip = {}
    proto_rank = {"socks5": 0, "https": 1, "http": 2}
    for p in sorted(pool, key=lambda x: (0 if x["anonymity"] == "High" else 1, proto_rank.get(x["type"], 9), x.get("latency_ms", 99999))):
        if p["ip"] not in best_by_ip:
            best_by_ip[p["ip"]] = p

    candidates = list(best_by_ip.values())[:35]

    enriched = []
    for p in candidates:
        ipinfo, scam = check_ip_quality(p["ip"])
        if ipinfo.get("country") and ipinfo.get("country") != "AU":
            continue
        org = ipinfo.get("org", "")
        org_lower = org.lower()
        is_isp = (scam["datacenter"] == "No") or any(k in org_lower for k in ISP_KEYWORDS)
        enriched.append({
            **p,
            "org_name": org.split(" ", 1)[1] if " " in org else org,
            "is_isp": is_isp,
            "score": scam["score"],
            "blacklists": scam["blacklists"],
        })

    # Rank: low risk (<20) & ISP preferred > low score > fewer blacklists > High anon > latency
    enriched.sort(key=lambda x: (
        0 if x["score"] <= 15 else 1,
        0 if x["is_isp"] else 1,
        x["score"],
        x["blacklists"],
        0 if x["anonymity"] == "High" else 1,
        x.get("latency_ms", 99999),
    ))

    top10 = enriched[:10]
    if len(top10) < 3:
        raise RuntimeError("Too few valid AU proxies found; keeping existing file.")

    yaml_text = build_clash_yaml(top10)
    with open("au_top10_clash.yaml", "w", encoding="utf-8") as f:
        f.write(yaml_text)
    print(f"Successfully wrote {len(top10)} proxies to au_top10_clash.yaml")


if __name__ == "__main__":
    main()
