import concurrent.futures
import re
import time
import requests
import yaml
from bs4 import BeautifulSoup

TARGETS = [
    ("AU", "au_top10_clash.yaml"),
    ("CN", "cn_top10_clash.yaml"),
]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

ISP_KEYWORDS_BY_COUNTRY = {
    "CN": ("chinanet", "china telecom", "chinatelecom", "china unicom", "china169", "china mobile", "cmcc", "cernet", "cstnet", "cncgroup", "tietong", "dr.peng"),
    "AU": ("aussie", "telstra", "optus", "tpg", "vocus", "internode", "iinet", "superloop", "aussie fibre", "dicker", "intervolve", "aapt", "vodafone"),
}

CN_REGION_MAP = {
    "Beijing": "北京", "Shanghai": "上海", "Tianjin": "天津", "Chongqing": "重庆",
    "Guangdong": "广东", "Zhejiang": "浙江", "Jiangsu": "江苏", "Sichuan": "四川",
    "Hubei": "湖北", "Hunan": "湖南", "Fujian": "福建", "Shandong": "山东",
    "Henan": "河南", "Hebei": "河北", "Liaoning": "辽宁", "Jilin": "吉林",
    "Heilongjiang": "黑龙江", "Anhui": "安徽", "Jiangxi": "江西", "Shaanxi": "陕西",
    "Shanxi": "山西", "Yunnan": "云南", "Guizhou": "贵州", "Guangxi": "广西",
    "Hainan": "海南", "Gansu": "甘肃", "Qinghai": "青海", "Ningxia": "宁夏",
    "Xinjiang": "新疆", "Tibet": "西藏", "Inner Mongolia": "内蒙古",
    "Hong Kong": "香港", "Macao": "澳门", "Taiwan": "台湾",
}

CN_CITY_MAP = {
    "Beijing": "北京", "Shanghai": "上海", "Tianjin": "天津", "Chongqing": "重庆",
    "Guangzhou": "广州", "Shenzhen": "深圳", "Dongguan": "东莞", "Foshan": "佛山",
    "Hangzhou": "杭州", "Ningbo": "宁波", "Wenzhou": "温州", "Nanjing": "南京",
    "Suzhou": "苏州", "Wuxi": "无锡", "Chengdu": "成都", "Wuhan": "武汉",
    "Changsha": "长沙", "Xiamen": "厦门", "Fuzhou": "福州", "Jinan": "济南",
    "Qingdao": "青岛", "Zhengzhou": "郑州", "Shijiazhuang": "石家庄", "Shenyang": "沈阳",
    "Dalian": "大连", "Harbin": "哈尔滨", "Changchun": "长春", "Hefei": "合肥",
    "Nanchang": "南昌", "Xi'an": "西安", "Kunming": "昆明", "Guiyang": "贵阳",
    "Nanning": "南宁", "Haikou": "海口", "Taiyuan": "太原", "Lanzhou": "兰州",
    "Urumqi": "乌鲁木齐", "Hohhot": "呼和浩特",
}


def format_isp_cn(org_name):
    low = org_name.lower()
    if any(k in low for k in ("chinanet", "china telecom", "chinatelecom")):
        return "电信"
    if any(k in low for k in ("unicom", "china169", "cncgroup")):
        return "联通"
    if any(k in low for k in ("mobile", "cmcc", "tietong")):
        return "移动"
    if "cernet" in low or "edu" in low:
        return "教育网"
    return re.sub(r"[^A-Za-z0-9]+", "", org_name)[:12] or "CN"


def format_location(country_code, region, city):
    if country_code == "CN":
        r_zh = CN_REGION_MAP.get(region, region)
        c_zh = CN_CITY_MAP.get(city, city)
        parts = [p for p in (r_zh, c_zh) if p]
        if len(parts) == 2 and parts[0] == parts[1]:
            return parts[0]
        return "".join(parts) if parts else "中国"
    parts = [p for p in (city, region) if p]
    if city:
        return re.sub(r"[^A-Za-z0-9]+", "", city)[:14]
    if region:
        return re.sub(r"[^A-Za-z0-9]+", "", region)[:14]
    return country_code


def add_proxy(pool, seen, ip, port, ptype, anon="Unknown"):
    ptype = ptype.lower().strip()
    if ptype == "http https":
        ptype = "https"
    if ptype not in ("http", "https", "socks5"):
        return
    if not ip or not str(port).isdigit():
        return
    port = int(port)
    key = (ip, port, ptype)
    if key not in seen:
        seen.add(key)
        pool.append({"ip": ip, "port": port, "type": ptype, "anonymity": anon})


def fetch_freeproxy_world(country_code, pool, seen, max_pages=5):
    url_tpl = f"https://www.freeproxy.world/?type=&anonymity=&country={country_code}&speed=&port=&page={{page}}"
    for page in range(1, max_pages + 1):
        try:
            r = requests.get(url_tpl.format(page=page), headers={"User-Agent": UA}, timeout=15)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            table = soup.find("table")
            if not table:
                continue
            for tr in table.find_all("tr"):
                cols = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
                if len(cols) >= 8:
                    add_proxy(pool, seen, cols[0], cols[1], cols[5], cols[6])
        except Exception as e:
            print(f"[{country_code} FreeProxyWorld p{page}] error: {e}")


def fetch_proxyscrape(country_code, pool, seen):
    url = f"https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&country={country_code.lower()}"
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=15)
        r.raise_for_status()
        for line in r.text.splitlines():
            m = re.match(r"^(https?|socks5)://([0-9.]+):(\d+)$", line.strip(), re.I)
            if m:
                add_proxy(pool, seen, m.group(2), m.group(3), m.group(1), "Unknown")
    except Exception as e:
        print(f"[{country_code} ProxyScrape] error: {e}")


def fetch_free_proxy_list(country_code, pool, seen):
    for url in ("https://free-proxy-list.net/", "https://www.socks-proxy.net/"):
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=15)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            table = soup.find("table")
            if not table:
                continue
            for tr in table.select("tbody tr"):
                cols = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
                if len(cols) >= 7 and cols[2].upper() == country_code:
                    if "socks" in url:
                        ptype = "socks5" if "socks5" in cols[4].lower() else "http"
                        anon = cols[4]
                    else:
                        ptype = "https" if cols[6].lower() == "yes" else "http"
                        anon = "High" if "elite" in cols[4].lower() else cols[4]
                    add_proxy(pool, seen, cols[0], cols[1], ptype, anon)
        except Exception as e:
            print(f"[{country_code} FreeProxyList {url}] error: {e}")


def fetch_spys_one(country_code, pool, seen):
    url = f"https://spys.one/free-proxy-list/{country_code}/"
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=15)
        r.raise_for_status()
        html = r.text
        vars_map = {}
        for m in re.finditer(r"([A-Za-z0-9_]+)=([0-9A-Za-z_^]+);", html):
            name, expr = m.group(1), m.group(2)
            parts = expr.split("^")
            if len(parts) == 1 and parts[0].isdigit():
                vars_map[name] = int(parts[0])
            elif len(parts) == 2:
                v1 = int(parts[0]) if parts[0].isdigit() else vars_map.get(parts[0])
                v2 = int(parts[1]) if parts[1].isdigit() else vars_map.get(parts[1])
                if v1 is not None and v2 is not None:
                    vars_map[name] = v1 ^ v2

        soup = BeautifulSoup(html, "html.parser")
        for tr in soup.select("tr.spy1x, tr.spy1xx"):
            row_html = str(tr)
            ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", row_html)
            port_m = re.search(r'document\.write\(":"\+([^)]+)\)', row_html)
            if not ip_m or not port_m:
                continue
            ip = ip_m.group(1)
            digits = []
            for pair in re.findall(r"\(([^)]+)\)", port_m.group(1)):
                a_b = pair.split("^")
                if len(a_b) == 2 and a_b[0] in vars_map and a_b[1] in vars_map:
                    digits.append(str(vars_map[a_b[0]] ^ vars_map[a_b[1]]))
            port = "".join(digits)
            if not port.isdigit():
                continue
            text = tr.get_text(" ", strip=True).upper()
            ptype = "socks5" if "SOCKS5" in text else ("https" if "HTTPS" in text else "http")
            anon = "High" if ("HIA" in text or "ANM" in text) else "No"
            add_proxy(pool, seen, ip, port, ptype, anon)
    except Exception as e:
        print(f"[{country_code} Spys.one] error: {e}")


def test_connectivity(country_code, proxy):
    ptype = proxy["type"]
    scheme = "socks5h" if ptype == "socks5" else ptype
    proxy_url = f"{scheme}://{proxy['ip']}:{proxy['port']}"
    proxies_cfg = {"http": proxy_url, "https": proxy_url}
    start = time.time()
    try:
        r = requests.get(
            "http://ip-api.com/json/?fields=countryCode",
            proxies=proxies_cfg,
            timeout=6,
            headers={"User-Agent": UA},
        )
        latency_ms = int((time.time() - start) * 1000)
        if r.status_code == 200 and r.json().get("countryCode") == country_code:
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


def build_clash_yaml(country_code, selected):
    proxies = []
    names = []
    for idx, item in enumerate(selected, 1):
        loc = format_location(country_code, item.get("region", ""), item.get("city", ""))
        if country_code == "CN":
            isp = format_isp_cn(item.get("org_name", ""))
        else:
            isp = re.sub(r"[^A-Za-z0-9]+", "", item.get("org_name", country_code))[:12] or country_code
        proto_tag = item["type"].upper()
        name = f"{country_code}-{idx:02d}-{loc}-{isp}-{proto_tag}"
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
                "name": f"{country_code}-Select",
                "type": "select",
                "proxies": [f"{country_code}-Auto"] + names + ["DIRECT"],
            },
            {
                "name": f"{country_code}-Auto",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": names,
            },
        ],
        "rules": [f"MATCH,{country_code}-Select"],
    }
    return yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True)


def run_for_country(country_code, output_file):
    pool, seen = [], set()
    fetch_freeproxy_world(country_code, pool, seen, max_pages=5)
    fetch_proxyscrape(country_code, pool, seen)
    fetch_free_proxy_list(country_code, pool, seen)
    fetch_spys_one(country_code, pool, seen)

    print(f"[{country_code}] Total unique proxies fetched: {len(pool)}")
    if not pool:
        print(f"[{country_code}] No proxies fetched; skipping.")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        tested = list(ex.map(lambda p: test_connectivity(country_code, p), pool[:250]))

    alive = [p for p in tested if p["alive"]]
    print(f"[{country_code}] Live proxies verified: {len(alive)}")

    use_pool = alive if len(alive) >= 10 else pool

    best_by_ip = {}
    proto_rank = {"socks5": 0, "https": 1, "http": 2}
    for p in sorted(use_pool, key=lambda x: (0 if x["anonymity"] == "High" else 1, proto_rank.get(x["type"], 9), x.get("latency_ms", 99999))):
        if p["ip"] not in best_by_ip:
            best_by_ip[p["ip"]] = p

    candidates = list(best_by_ip.values())[:35]
    isp_keywords = ISP_KEYWORDS_BY_COUNTRY.get(country_code, ())

    enriched = []
    for p in candidates:
        ipinfo, scam = check_ip_quality(p["ip"])
        if ipinfo.get("country") and ipinfo.get("country") != country_code:
            continue
        org = ipinfo.get("org", "")
        org_lower = org.lower()
        is_isp = (scam["datacenter"] == "No") or any(k in org_lower for k in isp_keywords)
        enriched.append({
            **p,
            "region": ipinfo.get("region", ""),
            "city": ipinfo.get("city", ""),
            "org_name": org.split(" ", 1)[1] if " " in org else org,
            "is_isp": is_isp,
            "score": scam["score"],
            "blacklists": scam["blacklists"],
        })

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
        print(f"[{country_code}] Too few valid proxies ({len(top10)}); keeping existing {output_file}.")
        return

    yaml_text = build_clash_yaml(country_code, top10)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(yaml_text)
    print(f"[{country_code}] Successfully wrote {len(top10)} proxies to {output_file}")


def main():
    for country_code, output_file in TARGETS:
        run_for_country(country_code, output_file)


if __name__ == "__main__":
    main()