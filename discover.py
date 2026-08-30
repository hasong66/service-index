#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口发现 / 服务识别
================================================================
给「服务索引」用的一个小型扫描器：对指定主机做 TCP connect 扫描，
再对开着的端口做一次轻量探测，猜出上面跑的是什么。

为什么不用 nmap
----------------------------------------------------------------
镜像里不想多塞一个几十兆的二进制，而且我们要的只是“家里这台机器上
开了哪些端口、分别是什么服务”，标准库的 socket + 一点点指纹就够了。

探测顺序（每个开放端口只做这一遍，不做暴力猜测）
----------------------------------------------------------------
  1. 连上去先静听 0.6 秒 —— SSH / FTP / SMTP / MySQL 这类协议是
     服务端先开口，能直接拿到 banner。
  2. 没人开口就发一个 `GET /`：
       - 回 `HTTP/` 开头 -> HTTP 服务，解析状态码 / Server / 标题
       - 回 TLS 告警或直接断开 -> 换 TLS 重连再发一次，顺便读证书里的
         域名（自签证书的 CN 往往就写着 synology / proxmox 这种关键词）
       - 回别的东西 -> 当成 banner 处理。Redis / PostgreSQL / MongoDB
         被喂了一段 HTTP 请求都会回一句很有辨识度的报错，正好用来认人。

识别优先级：指纹命中 > 网页标题 > 端口惯例 > 只报协议。
越靠后越不可信，结果里用 confidence 标出来，前端会显示成“疑似”。
"""

import ipaddress
import random
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape

try:
    from cryptography import x509
except ImportError:              # 没有 cryptography 也能跑，只是读不到证书
    x509 = None


# ---------------------------------------------------------------------------
# 参数上限（防止一次请求把机器打满）
# ---------------------------------------------------------------------------
MAX_PORTS = 65535
MAX_CONCURRENCY = 512
SENTINEL_COUNT = 3             # 开扫前先试几个几乎不可能开放的高位端口
SCAN_CHUNK = 4096              # 每批提交多少个连接任务，避免一次性建 6 万个 future
BODY_LIMIT = 64 * 1024         # 抓网页正文的上限
PROGRESS_INTERVAL = 0.25       # 进度事件最小间隔（秒）


# ---------------------------------------------------------------------------
# 常用端口：自托管圈子里能叫得上名字的那些
# ---------------------------------------------------------------------------
COMMON_PORTS = sorted({
    # 基础服务
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 548, 587, 631, 873, 993, 995, 1433, 1521, 1883, 2049, 2375, 2376,
    3128, 3306, 3389, 5432, 5900, 5901, 6379, 8443, 9200, 11211, 27017,
    # Web / 应用（3000 段）
    3000, 3001, 3002, 3003, 3005, 3100,
    # 5000 段
    5000, 5001, 5006, 5010, 5030, 5055, 5080, 5230, 5232, 5244, 5299,
    5433, 5601, 5678, 5800, 5984,
    # 6000-7000 段
    6767, 6789, 6800, 6881, 7000, 7001, 7070, 7359, 7777, 7878,
    # 8000 段（重灾区）
    8000, 8001, 8002, 8006, 8008, 8009, 8010, 8020, 8069, 8080, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8096,
    8097, 8098, 8112, 8118, 8123, 8181, 8191, 8200, 8222, 8384, 8388,
    8444, 8500, 8686, 8765, 8787, 8800, 8880, 8888, 8889, 8920, 8989,
    # 9000 段
    9000, 9001, 9002, 9010, 9090, 9091, 9092, 9093, 9095, 9096, 9117,
    9443, 9696, 9800, 9981, 9999,
    # 五位数
    10000, 10001, 11434, 13378, 15672, 18080, 19999, 20000, 21064,
    22000, 25565, 26500, 28981, 32400, 32469, 33060, 34400, 51413,
    55000, 61208,
})


# ---------------------------------------------------------------------------
# 端口惯例：只在没别的线索时兜底，所以标成低可信度
# ---------------------------------------------------------------------------
PORT_HINTS = {
    21:    ("FTP", "📁", "存储"),
    22:    ("SSH", "🔑", "运维"),
    23:    ("Telnet", "🔑", "运维"),
    25:    ("SMTP", "✉️", "邮件"),
    53:    ("DNS", "🛡", "网络"),
    80:    ("Web 服务", "🌐", "应用"),
    81:    ("Nginx Proxy Manager", "🔀", "运维"),
    110:   ("POP3", "✉️", "邮件"),
    139:   ("SMB", "📁", "存储"),
    143:   ("IMAP", "✉️", "邮件"),
    389:   ("LDAP", "🔐", "运维"),
    443:   ("Web 服务 (HTTPS)", "🌐", "应用"),
    445:   ("SMB 共享", "📁", "存储"),
    548:   ("AFP 共享", "📁", "存储"),
    631:   ("CUPS 打印", "🖨", "应用"),
    873:   ("rsync", "🔄", "存储"),
    1433:  ("SQL Server", "🗄", "数据库"),
    1521:  ("Oracle DB", "🗄", "数据库"),
    1883:  ("MQTT", "📡", "智能家居"),
    2049:  ("NFS", "📁", "存储"),
    2375:  ("Docker API", "🐳", "运维"),
    2376:  ("Docker API (TLS)", "🐳", "运维"),
    3000:  ("Web 应用", "🌐", "应用"),
    3001:  ("Uptime Kuma", "📈", "监控"),
    3306:  ("MySQL / MariaDB", "🗄", "数据库"),
    3389:  ("远程桌面", "🖥", "运维"),
    5000:  ("服务索引", "🧭", "运维"),
    5001:  ("Dockge", "🐳", "运维"),
    5055:  ("Overseerr", "🎫", "媒体"),
    5230:  ("Memos", "📝", "应用"),
    5244:  ("AList", "📁", "存储"),
    5432:  ("PostgreSQL", "🐘", "数据库"),
    5601:  ("Kibana", "📊", "监控"),
    5678:  ("n8n", "🔗", "自动化"),
    5900:  ("VNC", "🖥", "运维"),
    5984:  ("CouchDB", "🗄", "数据库"),
    6379:  ("Redis", "🗄", "数据库"),
    6800:  ("Aria2 RPC", "📥", "下载"),
    6881:  ("BT 传输", "📥", "下载"),
    7878:  ("Radarr", "🎞", "媒体"),
    8006:  ("Proxmox VE", "🖥", "虚拟化"),
    8080:  ("Web 应用", "🌐", "应用"),
    8083:  ("Calibre-Web", "📚", "应用"),
    8086:  ("InfluxDB", "📊", "监控"),
    8090:  ("Halo", "📝", "应用"),
    8096:  ("Jellyfin", "🎬", "媒体"),
    8112:  ("Deluge", "📥", "下载"),
    8123:  ("Home Assistant", "🏡", "智能家居"),
    8191:  ("FlareSolverr", "🧩", "下载"),
    8200:  ("Duplicati", "💾", "存储"),
    8222:  ("Vaultwarden", "🔐", "应用"),
    8384:  ("Syncthing", "🔄", "存储"),
    8686:  ("Lidarr", "🎵", "媒体"),
    8920:  ("Emby / Jellyfin (HTTPS)", "🎬", "媒体"),
    8989:  ("Sonarr", "📺", "媒体"),
    9000:  ("Portainer", "🐳", "运维"),
    9091:  ("Transmission", "📥", "下载"),
    9090:  ("Prometheus / Cockpit", "📊", "监控"),
    9117:  ("Jackett", "🔍", "下载"),
    9200:  ("Elasticsearch", "🔍", "数据库"),
    9443:  ("Portainer (HTTPS)", "🐳", "运维"),
    9696:  ("Prowlarr", "🔍", "下载"),
    9981:  ("Tvheadend", "📺", "媒体"),
    10000: ("Webmin", "🖥", "运维"),
    11434: ("Ollama", "🤖", "AI"),
    13378: ("Audiobookshelf", "📚", "应用"),
    15672: ("RabbitMQ", "🐰", "运维"),
    19999: ("Netdata", "📊", "监控"),
    22000: ("Syncthing 同步", "🔄", "存储"),
    25565: ("Minecraft", "🎮", "游戏"),
    27017: ("MongoDB", "🍃", "数据库"),
    32400: ("Plex", "🎬", "媒体"),
    51413: ("Transmission 传输", "📥", "下载"),
    61208: ("Glances", "📊", "监控"),
}


# ---------------------------------------------------------------------------
# 指纹：(正则, 名称, 图标, 分类, 是否强特征)
# 强特征 = 命中即高可信；弱特征（nginx / apache 这种通用中间件）只算中等。
# 匹配对象是把标题、Server 头、认证 realm、banner、证书域名、跳转地址
# 拼起来的一段小文本，全部转小写。
# ---------------------------------------------------------------------------
SIGNATURES = [
    # ---- 媒体 ----
    (r"jellyfin",                      "Jellyfin",            "🎬", "媒体",     True),
    (r"\bemby\b",                      "Emby",                "🎬", "媒体",     True),
    (r"\bplex\b",                      "Plex",                "🎬", "媒体",     True),
    (r"navidrome",                     "Navidrome",           "🎵", "媒体",     True),
    (r"tautulli",                      "Tautulli",            "📊", "媒体",     True),
    (r"\bsonarr\b",                    "Sonarr",              "📺", "媒体",     True),
    (r"\bradarr\b",                    "Radarr",              "🎞", "媒体",     True),
    (r"\blidarr\b",                    "Lidarr",              "🎵", "媒体",     True),
    (r"\bbazarr\b",                    "Bazarr",              "💬", "媒体",     True),
    (r"\breadarr\b",                   "Readarr",             "📚", "媒体",     True),
    (r"jellyseerr",                    "Jellyseerr",          "🎫", "媒体",     True),
    (r"overseerr",                     "Overseerr",           "🎫", "媒体",     True),
    (r"tvheadend",                     "Tvheadend",           "📺", "媒体",     True),
    (r"\bkodi\b",                      "Kodi",                "🎬", "媒体",     True),
    # ---- 下载 ----
    (r"qbittorrent",                   "qBittorrent",         "📥", "下载",     True),
    (r"transmission",                  "Transmission",        "📥", "下载",     True),
    (r"\bdeluge\b",                    "Deluge",              "📥", "下载",     True),
    (r"aria2|ariang",                  "Aria2",               "📥", "下载",     True),
    (r"\bprowlarr\b",                  "Prowlarr",            "🔍", "下载",     True),
    (r"\bjackett\b",                   "Jackett",             "🔍", "下载",     True),
    (r"flaresolverr",                  "FlareSolverr",        "🧩", "下载",     True),
    # ---- 智能家居 ----
    (r"home ?assistant|hass\.io",      "Home Assistant",      "🏡", "智能家居", True),
    (r"zigbee2mqtt",                   "Zigbee2MQTT",         "📡", "智能家居", True),
    (r"esphome",                       "ESPHome",             "📡", "智能家居", True),
    (r"node-?red",                     "Node-RED",            "🔗", "自动化",   True),
    (r"frigate",                       "Frigate",             "📹", "智能家居", True),
    (r"emqx|mosquitto",                "MQTT Broker",         "📡", "智能家居", True),
    # ---- 运维 / 容器 ----
    (r"dockge",                        "Dockge",              "🐳", "运维",     True),
    (r"portainer",                     "Portainer",           "🐳", "运维",     True),
    (r"nginx proxy manager",           "Nginx Proxy Manager", "🔀", "运维",     True),
    (r"\btraefik\b",                   "Traefik",             "🔀", "运维",     True),
    (r"\bcaddy\b",                     "Caddy",               "🔀", "运维",     True),
    (r"watchtower",                    "Watchtower",          "🐳", "运维",     True),
    (r"\bcockpit\b",                   "Cockpit",             "🖥", "运维",     True),
    (r"\bwebmin\b",                    "Webmin",              "🖥", "运维",     True),
    (r"rancher",                       "Rancher",             "🐮", "运维",     True),
    # ---- 监控 ----
    (r"grafana",                       "Grafana",             "📊", "监控",     True),
    (r"prometheus",                    "Prometheus",          "📊", "监控",     True),
    (r"uptime ?kuma",                  "Uptime Kuma",         "📈", "监控",     True),
    (r"netdata",                       "Netdata",             "📊", "监控",     True),
    (r"glances",                       "Glances",             "📊", "监控",     True),
    (r"zabbix",                        "Zabbix",              "📊", "监控",     True),
    (r"\bkibana\b",                    "Kibana",              "📊", "监控",     True),
    # ---- 存储 / 文件 ----
    (r"nextcloud",                     "Nextcloud",           "☁️", "存储",     True),
    (r"owncloud",                      "ownCloud",            "☁️", "存储",     True),
    (r"\balist\b",                     "AList",               "📁", "存储",     True),
    (r"\bzfile\b",                     "zFile",               "📁", "存储",     True),
    (r"syncthing",                     "Syncthing",           "🔄", "存储",     True),
    (r"file ?browser",                 "File Browser",        "📁", "存储",     True),
    (r"seafile",                       "Seafile",             "☁️", "存储",     True),
    (r"\bminio\b",                     "MinIO",               "🪣", "存储",     True),
    (r"duplicati",                     "Duplicati",           "💾", "存储",     True),
    (r"cloudreve",                     "Cloudreve",           "📁", "存储",     True),
    # ---- 相册 ----
    (r"immich",                        "Immich",              "📷", "相册",     True),
    (r"photoprism",                    "PhotoPrism",          "📷", "相册",     True),
    (r"lychee",                        "Lychee",              "📷", "相册",     True),
    # ---- NAS / 虚拟化 ----
    (r"proxmox|\bpve\b",               "Proxmox VE",          "🖥", "虚拟化",   True),
    (r"synology|diskstation|\bdsm\b",  "群晖 DSM",            "🖥", "NAS",      True),
    (r"\bqnap\b|\bqts\b",              "QNAP",                "🖥", "NAS",      True),
    (r"truenas|freenas",               "TrueNAS",             "🖥", "NAS",      True),
    (r"unraid",                        "Unraid",              "🖥", "NAS",      True),
    (r"\besxi\b|vmware",               "VMware ESXi",         "🖥", "虚拟化",   True),
    # ---- 网络 ----
    (r"openwrt|\bluci\b",              "OpenWrt",             "🛜", "网络",     True),
    (r"pfsense",                       "pfSense",             "🛜", "网络",     True),
    (r"opnsense",                      "OPNsense",            "🛜", "网络",     True),
    (r"\bunifi\b",                     "UniFi",               "🛜", "网络",     True),
    (r"adguard",                       "AdGuard Home",        "🛡", "网络",     True),
    (r"pi-?hole",                      "Pi-hole",             "🛡", "网络",     True),
    (r"wg-?easy|wireguard",            "WireGuard",           "🔒", "网络",     True),
    (r"\bzerotier\b",                  "ZeroTier",            "🔒", "网络",     True),
    (r"\btailscale\b|headscale",       "Tailscale",           "🔒", "网络",     True),
    # ---- 开发 ----
    (r"\bgitea\b|forgejo",             "Gitea",               "🌱", "开发",     True),
    (r"\bgitlab\b",                    "GitLab",              "🦊", "开发",     True),
    (r"jenkins",                       "Jenkins",             "🧰", "开发",     True),
    (r"sonarqube",                     "SonarQube",           "🧰", "开发",     True),
    (r"code-?server",                  "code-server",         "💻", "开发",     True),
    (r"jupyter",                       "Jupyter",             "📓", "开发",     True),
    (r"\bharbor\b",                    "Harbor",              "🐳", "开发",     True),
    # ---- 应用 ----
    (r"vaultwarden|bitwarden",         "Vaultwarden",         "🔐", "应用",     True),
    (r"\bhalo\b",                      "Halo",                "📝", "应用",     True),
    (r"wordpress|wp-content",          "WordPress",           "📝", "应用",     True),
    (r"\bmemos\b",                     "Memos",               "📝", "应用",     True),
    (r"bookstack",                     "BookStack",           "📚", "应用",     True),
    (r"\boutline\b",                   "Outline",             "📝", "应用",     True),
    (r"calibre",                       "Calibre-Web",         "📚", "应用",     True),
    (r"audiobookshelf",                "Audiobookshelf",      "📚", "应用",     True),
    (r"vikunja|\bwekan\b",             "任务看板",            "✅", "应用",     True),
    (r"\bn8n\b",                       "n8n",                 "🔗", "自动化",   True),
    (r"homarr|heimdall|\bdashy\b|homepage", "导航页",         "🧭", "运维",     True),
    (r"rustdesk",                      "RustDesk",            "🖥", "运维",     True),
    (r"keycloak",                      "Keycloak",            "🔐", "运维",     True),
    (r"authelia|authentik",            "统一认证",            "🔐", "运维",     True),
    # ---- AI ----
    (r"open ?webui|\bollama\b",        "Open WebUI / Ollama", "🤖", "AI",       True),
    (r"stable ?diffusion|automatic1111|comfyui", "Stable Diffusion", "🎨", "AI", True),
    (r"lobe ?chat|\bnext ?chat\b",     "LobeChat",            "🤖", "AI",       True),
    # ---- 数据库 / 中间件（多半是被喂了 HTTP 请求后回的报错）----
    (r"it looks like you are trying to access mongodb", "MongoDB", "🍃", "数据库", True),
    (r"unsupported frontend protocol|invalid length of startup packet",
                                       "PostgreSQL",          "🐘", "数据库",   True),
    (r"mariadb",                       "MariaDB",             "🗄", "数据库",   True),
    (r"\bmysql\b|mysql_native_password", "MySQL",             "🗄", "数据库",   True),
    (r"-err unknown command|-err wrong number of arguments|redis",
                                       "Redis",               "🗄", "数据库",   True),
    (r"elasticsearch",                 "Elasticsearch",       "🔍", "数据库",   True),
    (r"influxdb",                      "InfluxDB",            "📊", "监控",     True),
    (r"rabbitmq",                      "RabbitMQ",            "🐰", "运维",     True),
    (r"clickhouse",                    "ClickHouse",          "🗄", "数据库",   True),
    (r"memcached",                     "Memcached",           "🗄", "数据库",   True),
    # ---- 老实巴交的 banner 协议 ----
    (r"^ssh-\d",                       "SSH",                 "🔑", "运维",     True),
    (r"vsftpd|filezilla server|pure-ftpd|proftpd|^220[ -].*ftp",
                                       "FTP",                 "📁", "存储",     True),
    (r"postfix|\bexim\b|^220[ -].*(smtp|esmtp)", "SMTP",       "✉️", "邮件",     True),
    (r"^\+ok",                         "POP3",                "✉️", "邮件",     True),
    (r"^\* ok.*imap",                  "IMAP",                "✉️", "邮件",     True),
    (r"^rfb \d",                       "VNC",                 "🖥", "运维",     True),
    # ---- 通用中间件：能认出来但说明不了跑的是什么应用 ----
    (r"openresty",                     "OpenResty",           "🌐", "应用",     False),
    (r"\bnginx\b",                     "Nginx 站点",          "🌐", "应用",     False),
    (r"apache|httpd",                  "Apache 站点",         "🌐", "应用",     False),
    (r"microsoft-iis|microsoft-httpapi", "IIS 站点",          "🌐", "应用",     False),
    (r"\btomcat\b",                    "Tomcat",              "🌐", "应用",     False),
    (r"werkzeug|gunicorn|\buvicorn\b", "Python 服务",         "🐍", "应用",     False),
    (r"express|\bnode\.js\b",          "Node 服务",           "🌐", "应用",     False),
]

_COMPILED = [(re.compile(p, re.I | re.M), n, i, c, s) for p, n, i, c, s in SIGNATURES]

# 这类标题没有信息量，不拿来当服务名
_JUNK_TITLE = re.compile(
    r"^(index|home|homepage|login|sign ?in|log ?in|welcome|dashboard|main|"
    r"untitled|document|new tab|react app|vite \+ \w+|app|test|redirecting\.{0,3}|"
    r"\d{3}( |-).*|error.*|forbidden|not found|unauthorized|bad request|"
    r"400|401|403|404|500|502|503)$",
    re.I,
)


# ---------------------------------------------------------------------------
# 端口写法解析
# ---------------------------------------------------------------------------
def parse_ports(spec):
    """把 "80,443,8000-9000" / "common" / "all" 解析成端口列表。"""
    spec = (spec or "").strip()
    if not spec or spec.lower() in ("common", "常用"):
        return list(COMMON_PORTS)
    if spec.lower() in ("all", "full"):
        return list(range(1, 65536))

    out = set()
    for chunk in re.split(r"[,\s;，、]+", spec):
        if not chunk:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:\s*[-~]\s*(\d{1,5}))?", chunk)
        if not m:
            raise ValueError("无法识别的端口写法：%s" % chunk)
        a = int(m.group(1))
        b = int(m.group(2) or a)
        if a > b:
            a, b = b, a
        if not (1 <= a <= 65535 and 1 <= b <= 65535):
            raise ValueError("端口必须在 1-65535 之间")
        out.update(range(a, b + 1))
    if not out:
        raise ValueError("没有指定要扫描的端口")
    if len(out) > MAX_PORTS:
        raise ValueError("一次最多扫描 %d 个端口" % MAX_PORTS)
    return sorted(out)


def resolve_target(host):
    """把主机名解析成 (ip, 地址族)。解析不了就抛 ValueError。"""
    host = (host or "").strip().strip("[]")
    if not host:
        raise ValueError("请填写要扫描的主机")
    if re.search(r"[\s/\\@]", host):
        raise ValueError("主机名不合法")
    try:
        info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("无法解析主机：%s" % host)
    if not info:
        raise ValueError("无法解析主机：%s" % host)
    family, _, _, _, sockaddr = info[0]
    return sockaddr[0], family


# 100.64.0.0/10 是运营商级 NAT 段，Tailscale / ZeroTier 就发这个段的地址。
# Python 3.13 起 is_private 不再把它算作私有，这里显式补上。
_SHARED = ipaddress.ip_network("100.64.0.0/10")


def is_private_target(ip):
    """只有内网 / 回环 / 链路本地 / 组网虚拟网段算“自己家”。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    return addr.version == 4 and addr in _SHARED


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------
def _is_open(ip, port, family, timeout):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def _sentinel_check(ip, family, timeout):
    """开扫之前先验一下这个目标值不值得扫。

    组网 / VPN 那种用户态网络栈（例如 NodeBabyLink、部分 frp/内网穿透实现）
    会对**任意**端口抢先完成 TCP 握手，于是 connect 全都成功，扫出来 65535 个
    “开放端口”，一条都不能信。这里挑几个几乎不可能有服务的高位端口试一下：
    要是全都能连上，那就不是端口开着，是这个地址在来者不拒。

    返回“意外连上了的哨兵端口”列表；全中才说明目标不可信。
    """
    picks = random.sample(range(49152, 65500), SENTINEL_COUNT)
    t = min(2.0, max(timeout, 1.0))          # 宁可慢一点，别误判成正常目标
    return [p for p in picks if _is_open(ip, p, family, t)]


def run(host, ip, family, ports, timeout=0.4, concurrency=256, probe_timeout=2.5):
    """扫描 + 识别，以事件流的形式往外吐（给 SSE 用）。

    事件类型：start / progress / scanned / found / done
    """
    total = len(ports)
    started = time.time()
    yield {"type": "start", "host": host, "ip": ip, "total": total}

    hit = _sentinel_check(ip, family, timeout)
    if len(hit) == SENTINEL_COUNT:
        yield {"type": "unreliable", "host": host, "ip": ip,
               "sentinels": sorted(hit),
               "message": "%s 对任意端口都会接受连接（随手试的 %s 这几个端口全都“通”，"
                          "它们几乎不可能真有服务）。这通常是组网 / VPN 的用户态网络栈"
                          "抢先完成了握手，扫描结果一条都不可信，所以就不往下扫了。"
                          % (ip, "、".join(str(p) for p in sorted(hit)))}
        return

    workers = max(8, min(int(concurrency), MAX_CONCURRENCY, total))
    open_ports = []
    done = 0
    last_emit = 0.0

    futs = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        try:
            # 分批提交：一次性挂 6 万个 future 太吃内存，进度也不好算
            for i in range(0, total, SCAN_CHUNK):
                batch = ports[i:i + SCAN_CHUNK]
                futs = {pool.submit(_is_open, ip, p, family, timeout): p for p in batch}
                for fut in as_completed(futs):
                    done += 1
                    try:
                        if fut.result():
                            open_ports.append(futs[fut])
                    except Exception:
                        pass
                    now = time.time()
                    if now - last_emit >= PROGRESS_INTERVAL or done == total:
                        last_emit = now
                        yield {"type": "progress", "done": done, "total": total,
                               "open": len(open_ports)}
        except GeneratorExit:
            # 浏览器把连接断了（点了停止 / 关了页面）。剩下的任务全取消，
            # 否则线程池还会闷头把这一批几千个端口扫完才肯退出。
            for f in futs:
                f.cancel()
            raise

    open_ports.sort()
    yield {"type": "scanned", "open": open_ports,
           "elapsed": round(time.time() - started, 1)}

    if open_ports:
        probes = max(1, min(24, len(open_ports)))
        with ThreadPoolExecutor(max_workers=probes) as pool:
            futs = {pool.submit(probe, host, ip, p, family, probe_timeout): p
                    for p in open_ports}
            for fut in as_completed(futs):
                port = futs[fut]
                try:
                    ev = fut.result()
                except Exception:
                    ev = {}
                yield dict(identify(port, ev), type="found")

    yield {"type": "done", "total": total, "open": len(open_ports),
           "elapsed": round(time.time() - started, 1)}


# ---------------------------------------------------------------------------
# 单个端口的探测
# ---------------------------------------------------------------------------
def probe(host, ip, port, family, timeout):
    """连上去看看是什么。返回一堆“证据”，判断交给 identify()。"""
    ev = {"proto": "tcp", "tls": False, "banner": "", "status": None,
          "server": "", "title": "", "realm": "", "location": "", "cert": ""}

    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
    except OSError:
        return ev

    try:
        # 1) 先听：SSH / FTP / SMTP / MySQL 这些是服务端先开口
        sock.settimeout(0.6)
        try:
            greeting = sock.recv(1024)
        except (socket.timeout, OSError):
            greeting = b""

        if greeting:
            ev["banner"] = _snippet(greeting)
            return ev

        # 2) 没人开口就发一个 HTTP 请求探路
        raw = _http_exchange(sock, _host_header(host, port), timeout)
    finally:
        _close(sock)

    if raw.startswith(b"HTTP/"):
        ev["proto"] = "http"
        _fill_http(ev, raw)
        # 有些服务（Syncthing、各种管理面板）在同一个端口上先用明文回一个
        # 301/307 把你赶到 https。这时候真正的信息在 TLS 那边，而且 scheme
        # 必须记成 https —— 否则加进索引的链接是点不开的。
        if _redirects_to_own_https(ev, port):
            tls_ev = _probe_tls(host, ip, port, family, timeout)
            if tls_ev:
                return tls_ev
        return ev

    # 3) 明文不通 —— 可能是 TLS，也可能是别的协议
    tls_ev = _probe_tls(host, ip, port, family, timeout)
    if tls_ev:
        return tls_ev
    if raw:
        ev["banner"] = _snippet(raw)
    return ev


def _redirects_to_own_https(ev, port):
    """这个响应是不是「跳到本端口的 https」。"""
    if ev.get("status") not in (301, 302, 303, 307, 308):
        return False
    loc = (ev.get("location") or "").strip().lower()
    if not loc.startswith("https://"):
        return False
    authority = loc[len("https://"):].split("/")[0]
    tail = authority.rsplit("]", 1)[-1]          # 兼容 [::1]:8384
    if ":" not in tail:
        return port == 443
    try:
        return int(tail.rpartition(":")[2]) == port
    except ValueError:
        return False


def _probe_tls(host, ip, port, family, timeout):
    """换 TLS 再来一次；顺便把证书里的域名捞出来（自签证书常常自报家门）。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # 家用设备上老证书 / 弱套件很常见
    except ssl.SSLError:
        pass

    try:
        raw_sock = socket.socket(family, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))
    except OSError:
        return None

    try:
        # SNI 只在主机名是域名时才发，IP 地址不能当 server_hostname
        sni = host if not _looks_like_ip(host) else None
        tls = ctx.wrap_socket(raw_sock, server_hostname=sni)
    except (ssl.SSLError, OSError, ValueError):
        _close(raw_sock)
        return None

    ev = {"proto": "https", "tls": True, "banner": "", "status": None,
          "server": "", "title": "", "realm": "", "location": "",
          "cert": _cert_names(tls)}
    try:
        raw = _http_exchange(tls, _host_header(host, port), timeout)
    finally:
        _close(tls)

    if raw.startswith(b"HTTP/"):
        _fill_http(ev, raw)
    else:
        ev["proto"] = "tls"
        if raw:
            ev["banner"] = _snippet(raw)
    return ev


def _http_exchange(sock, host_header, timeout, limit=BODY_LIMIT):
    req = (
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: ServiceIndex-Discover/1.0\r\n"
        "Accept: text/html,*/*\r\n"
        "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
        "Connection: close\r\n\r\n" % host_header
    )
    try:
        sock.settimeout(timeout)
        sock.sendall(req.encode("ascii", "ignore"))
    except OSError:
        return b""

    buf = b""
    while len(buf) < limit:
        try:
            chunk = sock.recv(8192)
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _fill_http(ev, raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")

    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
    if m:
        ev["status"] = int(m.group(1))

    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers.setdefault(k.strip().lower(), v.strip())

    ev["server"] = " ".join(filter(None, [
        headers.get("server", ""),
        headers.get("x-powered-by", ""),
        headers.get("x-application-name", ""),
    ]))[:160]
    ev["location"] = headers.get("location", "")[:200]

    auth = headers.get("www-authenticate", "")
    m = re.search(r'realm\s*=\s*"([^"]*)"', auth, re.I)
    ev["realm"] = (m.group(1) if m else auth)[:120]

    if headers.get("transfer-encoding", "").lower().find("chunked") >= 0:
        body = _dechunk(body)
    ev["title"] = _extract_title(body, headers.get("content-type", ""))

    # 正文里的一些强特征（比如 Home Assistant 的自定义标签）也留一小段
    ev["body"] = _body_markers(body)


def _dechunk(body):
    out = bytearray()
    i = 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            return body
        if size <= 0:
            break
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out) or body


def _extract_title(body, content_type):
    m = re.search(rb"<title[^>]*>(.*?)</title>", body[:BODY_LIMIT], re.I | re.S)
    if not m:
        return ""
    charset = "utf-8"
    cm = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    if cm:
        charset = cm.group(1)
    else:
        bm = re.search(rb'charset=["\']?([\w-]+)', body[:2048], re.I)
        if bm:
            charset = bm.group(1).decode("ascii", "ignore")
    try:
        text = m.group(1).decode(charset, "replace")
    except LookupError:
        text = m.group(1).decode("utf-8", "replace")
    return re.sub(r"\s+", " ", unescape(text)).strip()[:120]


def _body_markers(body):
    """从正文里挑几段可能有辨识度的片段，别把整页塞进指纹里。"""
    text = body[:16384].decode("utf-8", "replace")
    hits = []
    for pat in (r'name="generator"[^>]*content="([^"]{0,60})"',
                r'name="application-name"[^>]*content="([^"]{0,60})"',
                r'<meta[^>]*content="([^"]{0,60})"[^>]*name="generator"',
                r'\b(?:app|data)-name=["\']([\w .-]{2,40})["\']'):
        m = re.search(pat, text, re.I)
        if m:
            hits.append(m.group(1))
    return " ".join(hits)[:200]


def _cert_names(tls_sock):
    if x509 is None:
        return ""
    try:
        der = tls_sock.getpeercert(binary_form=True)
        if not der:
            return ""
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return ""
    names = []
    try:
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                names.append(str(attr.value))
            elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                names.append(str(attr.value))
    except Exception:
        pass
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names += san.value.get_values_for_type(x509.DNSName)[:4]
    except Exception:
        pass
    seen, out = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return " ".join(out)[:160]


# ---------------------------------------------------------------------------
# 识别
# ---------------------------------------------------------------------------
def identify(port, ev):
    ev = ev or {}
    proto = ev.get("proto") or "tcp"
    title = ev.get("title") or ""
    server = ev.get("server") or ""
    banner = ev.get("banner") or ""
    cert = ev.get("cert") or ""
    realm = ev.get("realm") or ""
    location = ev.get("location") or ""

    # 每条证据各占一行：SSH / FTP / POP3 那几条指纹是用 ^ 锚在行首的，
    # 拿空格拼会让 banner 挤到行中间，白白认不出来。
    hay = "\n".join(x for x in [title, server, realm, banner, cert, location,
                                ev.get("body") or ""] if x).lower()

    name = icon = category = ""
    confidence = "none"

    # 1) 指纹
    for rx, n, i, c, strong in _COMPILED:
        if rx.search(hay):
            name, icon, category = n, i, c
            confidence = "high" if strong else "medium"
            break

    # 2) 指纹只认出通用中间件（nginx 之类）时，网页标题往往更有信息量
    if confidence in ("none", "medium") and _title_usable(title):
        name = title
        confidence = "medium"
        if not icon:
            icon, category = "🌐", "应用"

    # 3) 端口惯例兜底
    if confidence == "none" and port in PORT_HINTS:
        name, icon, category = PORT_HINTS[port]
        confidence = "low"

    # 4) 实在认不出，就只说协议
    if not name:
        name = {"http": "HTTP 服务", "https": "HTTPS 服务",
                "tls": "TLS 服务"}.get(proto, "未知服务")
        icon, category = ("🌐", "应用") if proto in ("http", "https") else ("🔌", "其他")

    scheme = "https" if proto in ("https", "tls") else ("http" if proto == "http" else "")
    web = proto in ("http", "https")

    return {
        "port": port,
        "name": name,
        "icon": icon,
        "category": category or "应用",
        "scheme": scheme,
        "confidence": confidence,
        "web": web,
        "proto": proto,
        "status": ev.get("status"),
        "title": title,
        "server": server,
        "cert": cert,
        "realm": realm,
        "location": location,
        "banner": banner,
        "evidence": _evidence(ev),
    }


def _title_usable(title):
    t = (title or "").strip()
    if not (1 <= len(t) <= 48):
        return False
    if _JUNK_TITLE.match(t):
        return False
    if re.fullmatch(r"[\d.:/\[\]a-f-]+", t):    # 纯 IP / 端口
        return False
    return True


def _evidence(ev):
    """给前端显示一行“凭什么这么猜”。"""
    bits = []
    if ev.get("status"):
        bits.append("HTTP %s" % ev["status"])
    if ev.get("title"):
        bits.append("标题：%s" % ev["title"][:48])
    if ev.get("server"):
        bits.append("Server：%s" % ev["server"][:48])
    if ev.get("cert"):
        bits.append("证书：%s" % ev["cert"][:48])
    if ev.get("realm"):
        bits.append("认证域：%s" % ev["realm"][:32])
    if ev.get("location"):
        bits.append("跳转：%s" % ev["location"][:48])
    if ev.get("banner"):
        bits.append("Banner：%s" % ev["banner"][:64])
    return " · ".join(bits)


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _host_header(host, port):
    h = "[%s]" % host if ":" in host and not host.startswith("[") else host
    return h if port in (80, 443) else "%s:%d" % (h, port)


def _looks_like_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _snippet(data):
    text = data[:512].decode("utf-8", "replace")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", ".", text)
    return re.sub(r"\s+", " ", text).strip()[:200]


def _close(sock):
    try:
        sock.close()
    except OSError:
        pass
