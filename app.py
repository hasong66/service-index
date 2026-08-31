#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务索引 (Service Index)
================================================================
一个“网络感知”的自托管服务导航页。

核心能力
----------------------------------------------------------------
1. 网络感知跳转：根据你访问索引页所用的地址，自动判断当前处于哪种网络
   （内网 / 组网虚拟局域网 / 公网穿透域名），点击服务时使用对应网络下的地址。
   - 通过 index.example.com 访问 -> 跳转到各服务的穿透/反代域名
   - 通过 10.8.0.5:5000 访问     -> 跳转到组网地址 10.8.0.5:对应端口
   - 通过 192.168.1.50 访问      -> 跳转到内网地址 192.168.1.50:对应端口
2. 配置管理：所有服务用 YAML 配置文件维护（可手动编辑，也可在网页里增删改）。
3. 密码认证：密码经过哈希后加密存储在配置文件里，明文不落盘；
   且浏览器提交密码前先用服务端 RSA 公钥加密，明文不出现在请求体里
   （见 static/crypto.js，纯 HTTP 内网场景下 WebCrypto 不可用，故自带实现）。
4. 网页内添加服务：“是否内网穿透”为复选框，勾选后填写穿透/反代域名。
5. 端口发现：扫一遍目标主机的端口，顺带猜出每个端口上跑的是什么服务，
   一键把结果加进索引（见 discover.py）。

运行
----------------------------------------------------------------
  python app.py            # 开发模式启动 (默认 0.0.0.0:5000)
  python app.py setpw      # 在终端设置/重置访问密码
  gunicorn -b 0.0.0.0:5000 --preload app:app   # 生产模式
"""

import os
import sys
import ipaddress
import json
import time
import random
import base64
import socket
import secrets
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

import yaml
from flask import (
    Flask, request, session, jsonify, redirect, url_for, render_template,
    Response, send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import discover

# ---------------------------------------------------------------------------
# 配置文件
# ---------------------------------------------------------------------------
CONFIG_PATH = os.environ.get(
    "CONFIG_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
)

# 自定义背景存在 config.yaml 旁边（容器里就是 /data/uploads）。
#
# 不能放 static/ 下：那是镜像里的目录，`docker compose up -d --build` 一重建就没了，
# 而 config.yaml 还记着文件名 —— 结果就是背景莫名其妙变空白。这个项目的约定是
# 「状态一律在 /data」，上传的文件也不例外。
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(CONFIG_PATH)), "uploads")

# 背景文件。名字是固定的 bg-custom.<ext>：同时只允许存在一张，省得 uploads 目录
# 越攒越大，也让「文件名可控」这件事变成路径穿越的天然防线。
BG_STEM = "bg-custom"
BG_IMAGE_EXT = {"jpg", "jpeg", "png", "webp", "gif"}
BG_VIDEO_EXT = {"mp4", "webm"}
BG_EXT = BG_IMAGE_EXT | BG_VIDEO_EXT
BG_MIME = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "webp": "image/webp", "gif": "image/gif",
    "mp4": "video/mp4", "webm": "video/webm",
}
# 上传体积上限（字节）。这个值会挂到 MAX_CONTENT_LENGTH 上，由 Werkzeug 在解析
# 请求体的时候就掐断，不会先把整个文件收下来再回过头判断大小。
MAX_UPLOAD = 64 * 1024 * 1024

# 默认配置（首次启动且没有 config.yaml 时写入）。
#
# networks 和 services 都是空的 —— 这是故意的：这两样完全取决于用户自己的网段和
# 服务，塞任何“示例”进去都只会变成别人配置文件里的垃圾。首次打开网页会走一个
# 引导，根据你此刻访问用的地址把第一个网络填好。
DEFAULT_CONFIG = {
    "title": "服务索引",
    "secret_key": "",        # 自动生成，用于签名会话 cookie
    "password_hash": "",     # 首次访问网页 / 运行 `python app.py setpw` 时设置
    "transport_key": "",     # 自动生成的 RSA 私钥 (PEM)，用于解密前端提交的密码
    # 端口发现的默认参数。allow_public 默认关着：只允许扫内网 / 回环地址，
    # 以及 networks 里配置过的主机，免得这个接口被当成任意主机的端口扫描器。
    "discover": {
        "timeout": 0.4,          # 单个端口的连接超时（秒）
        "concurrency": 256,      # 并发连接数
        "allow_public": False,   # 是否允许扫描公网地址
    },
    # 自定义背景。None = 用主题自带的渐变底，也就是不设背景。
    # 网页上传之后变成 {"type": "image"|"video", "file": "bg-custom.jpg"}
    "background": None,
    # 首次启动留空，由网页引导填写（也可以直接手写 config.yaml，见 config.example.yaml）
    "networks": [],
    "services": [],
}


# ---------------------------------------------------------------------------
# 密码传输加密
# ---------------------------------------------------------------------------
# 浏览器不会再把密码明文放进请求体：它先 GET /api/pubkey 拿到这里的 RSA 公钥，
# 用 RSA-OAEP(SHA-256) 把 {"v","f","p","t","n"} 这样一个小 JSON 加密后再提交。
#   f = 字段名（login / setup / current / new），绑定用途，信封不能挪作他用
#   t = 时间戳（用服务端时间，避免客户端时钟不准），超时即拒
#   n = 一次性随机数，用于挡重放
#
# 私钥随 secret_key 一起存在 config.yaml 里，这样多 worker / 重启后都是同一把，
# 不会出现“A worker 发的公钥 B worker 解不开”。
#
# 边界说明：这防的是“同网段被动嗅听拿到明文密码”。中间人依然可以劫持会话
# cookie —— 想要真正的端到端安全，前面还是得套 HTTPS。
TRANSPORT_KEY_BITS = 2048
ENVELOPE_VERSION = 1
ENVELOPE_TTL = 300            # 信封有效期（秒）
_NONCE_CACHE_MAX = 4096       # 已用随机数上限，超出按最旧淘汰

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

_key_cache = {}               # PEM -> 私钥对象
_used_nonces = OrderedDict()  # nonce -> 过期时间戳


class DecryptError(ValueError):
    """信封解不开 / 不合法。对外只给笼统提示，不泄露具体哪一步失败。"""


def generate_transport_key():
    """生成一把 RSA 私钥并序列化成 PEM 文本（存进 config.yaml）。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=TRANSPORT_KEY_BITS)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def transport_key():
    """按 PEM 文本缓存私钥对象，避免每次请求都重新解析。"""
    pem = load_config().get("transport_key") or ""
    key = _key_cache.get(pem)
    if key is None:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
        _key_cache.clear()
        _key_cache[pem] = key
    return key


def _consume_nonce(nonce):
    """随机数只认一次。返回 False 表示重放。"""
    now = time.time()
    while _used_nonces:
        oldest, expires = next(iter(_used_nonces.items()))
        if expires > now:
            break
        _used_nonces.popitem(last=False)
    if nonce in _used_nonces:
        return False
    _used_nonces[nonce] = now + ENVELOPE_TTL
    while len(_used_nonces) > _NONCE_CACHE_MAX:
        _used_nonces.popitem(last=False)
    return True


def decrypt_password(blob, field):
    """解开一个前端信封，取出其中的密码明文。任何异常都统一成 DecryptError。"""
    generic = "密码解密失败，请刷新页面后重试"
    if not isinstance(blob, str) or not blob:
        raise DecryptError("密码需要加密后提交，请刷新页面")
    try:
        cipher = base64.b64decode(blob, validate=True)
    except Exception:
        raise DecryptError(generic)
    try:
        plain = transport_key().decrypt(cipher, _OAEP)
        data = json.loads(plain.decode("utf-8"))
    except Exception:
        raise DecryptError(generic)

    if not isinstance(data, dict) or data.get("v") != ENVELOPE_VERSION:
        raise DecryptError(generic)
    if data.get("f") != field:          # 防止把「当前密码」信封拿去当「新密码」用
        raise DecryptError(generic)

    ts = data.get("t")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        raise DecryptError(generic)
    if abs(time.time() * 1000 - ts) > ENVELOPE_TTL * 1000:
        raise DecryptError("请求已过期，请刷新页面后重试")

    nonce = data.get("n")
    if not isinstance(nonce, str) or not nonce or not _consume_nonce(nonce):
        raise DecryptError("请求已失效，请刷新页面后重试")

    pw = data.get("p")
    if not isinstance(pw, str):
        raise DecryptError(generic)
    return pw



def _deepcopy(obj):
    return json.loads(json.dumps(obj))


def _ensure_structure(cfg):
    """补全缺失字段，返回 (cfg, changed)。"""
    changed = False
    if not isinstance(cfg, dict):
        return _deepcopy(DEFAULT_CONFIG), True

    if "title" not in cfg:
        cfg["title"] = DEFAULT_CONFIG["title"]; changed = True
    if not cfg.get("secret_key"):
        cfg["secret_key"] = secrets.token_hex(32); changed = True
    if "password_hash" not in cfg:
        cfg["password_hash"] = ""; changed = True
    if not cfg.get("transport_key"):
        cfg["transport_key"] = generate_transport_key(); changed = True
    if not isinstance(cfg.get("discover"), dict):
        cfg["discover"] = _deepcopy(DEFAULT_CONFIG["discover"]); changed = True
    else:
        for k, v in DEFAULT_CONFIG["discover"].items():
            if k not in cfg["discover"]:
                cfg["discover"][k] = v; changed = True
    if "background" not in cfg:
        cfg["background"] = None; changed = True
    if "networks" not in cfg or cfg["networks"] is None:
        cfg["networks"] = []; changed = True
    if "services" not in cfg or cfg["services"] is None:
        cfg["services"] = []; changed = True

    for s in cfg["services"]:
        if not s.get("id"):
            s["id"] = secrets.token_hex(4); changed = True
    return cfg, changed


def load_config():
    if not os.path.exists(CONFIG_PATH):
        cfg = _deepcopy(DEFAULT_CONFIG)
        cfg["secret_key"] = secrets.token_hex(32)
        cfg["transport_key"] = generate_transport_key()
        save_config(cfg)
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    cfg, changed = _ensure_structure(cfg)
    if changed:
        save_config(cfg)
    return cfg


def save_config(cfg):
    """原子写入，避免写一半导致配置损坏。"""
    os.makedirs(os.path.dirname(os.path.abspath(CONFIG_PATH)), exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    os.replace(tmp, CONFIG_PATH)


# ---------------------------------------------------------------------------
# 网络识别（服务端给一个提示值；真正以浏览器地址栏 hostname 为准，前端会再算一次）
# ---------------------------------------------------------------------------
def app_title(cfg):
    """页面标题。环境变量 TITLE 优先，方便用镜像的人不改配置文件就能改标题。"""
    return (os.environ.get("TITLE") or "").strip() or cfg.get("title") or "服务索引"


def request_host():
    host = request.headers.get("X-Forwarded-Host") or request.host or ""
    host = host.split(",")[0].strip()
    if host.startswith("["):                 # IPv6 字面量 [::1]:5000
        host = host[1:].split("]")[0]
    else:
        host = host.split(":")[0]            # 去掉端口
    return host.lower()


def match_host(hostname, pattern):
    """支持： 精确 / *.domain.com (子域) / 192.168.* (前缀)。"""
    hostname = (hostname or "").lower()
    pattern = (pattern or "").lower()
    if not pattern:
        return False
    if pattern == hostname:
        return True
    if pattern.startswith("*."):             # *.example.com -> 以 .example.com 结尾
        return hostname.endswith(pattern[1:])
    if pattern.endswith("*"):                # 192.168.*  /  10.*
        return hostname.startswith(pattern[:-1])
    return False


def detect_network(cfg, hostname):
    for net in cfg.get("networks", []):
        for pat in net.get("match", []) or []:
            if match_host(hostname, pat):
                return net["id"]
    nets = cfg.get("networks", [])
    return nets[0]["id"] if nets else None


def suggest_network(hostname):
    """用“你此刻是通过什么地址打开这个页面的”反推第一个网络该怎么填。

    这是引导页唯一不需要用户动脑的地方：你能看到这个页面，就说明这个地址在当前
    网络下是通的，那它天然就是这台机器在这个网络里的地址。
    """
    h = (hostname or "").strip().lower()
    if not h:
        return None

    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None

    if ip is None:                       # 域名 -> 公网，按 domain 模式
        parts = [x for x in h.split(".") if x]
        if len(parts) < 2:
            return None
        root = ".".join(parts[-2:])
        return {"id": "public", "name": "公网", "icon": "🌐", "mode": "domain",
                "match": ["*." + root]}

    if ip.is_loopback:                   # localhost 猜不出网段，让用户自己填
        return None

    seg = h.split(".")
    if h.startswith("10."):
        pattern = "10.*"                 # 10/8 太大，只匹配第一段
    elif len(seg) >= 2:
        pattern = "%s.%s.*" % (seg[0], seg[1])
    else:
        pattern = h
    return {"id": "lan", "name": "内网", "icon": "🏠", "mode": "port",
            "host": h, "match": [pattern]}


def safe_bg_name(name):
    """只认我们自己写出去的那个文件名。

    上传接口写死了 bg-custom.<ext>，所以这里可以用白名单而不是路径规范化来挡
    穿越 —— 凡是对不上这个形状的一律当不存在。
    """
    if "." not in name:
        return False
    stem, ext = name.rsplit(".", 1)
    return stem == BG_STEM and ext.lower() in BG_EXT


def background_info(cfg):
    """把配置里的背景翻译成前端能直接用的 URL；没有 / 文件丢了都返回 None。

    文件可能不在：手动删过 data/uploads，或者从别的机器拷了份 config.yaml 过来。
    这时候返回 None 让前端回落到默认渐变底，而不是渲染一个加载失败的 <img>。
    """
    bg = cfg.get("background")
    if not isinstance(bg, dict):
        return None
    name = bg.get("file") or ""
    kind = bg.get("type")
    if kind not in ("image", "video") or not safe_bg_name(name):
        return None
    path = os.path.join(UPLOAD_DIR, name)
    if not os.path.exists(path):
        return None
    # 文件名固定，换一张图名字不变 —— 不带版本号的话浏览器会拿缓存里的旧图。
    return {
        "type": kind,
        "url": "/bg/%s?v=%d" % (name, int(os.path.getmtime(path))),
        "mime": BG_MIME.get(name.rsplit(".", 1)[-1].lower(), ""),
    }


def public_config(cfg):
    """返回给前端的安全配置（剔除 secret_key / password_hash / transport_key）。"""
    host = request_host()
    networks = cfg.get("networks") or []
    return {
        "title": app_title(cfg),
        "networks": networks,
        "services": cfg.get("services", []),
        "detected": detect_network(cfg, host),
        "host": host,
        # 一个网络都没有 -> 前端显示引导页，而不是一张空网格
        "needs_networks": not networks,
        "suggest": suggest_network(host) if not networks else None,
        # None = 没设背景，前端用主题自带的渐变底
        "background": background_info(cfg),
    }


# ---------------------------------------------------------------------------
# 服务字段校验 / 清洗
# ---------------------------------------------------------------------------
def clean_service(data, existing=None):
    """校验并归一化一条服务记录（不含 id）。校验失败抛 ValueError。"""
    s = dict(existing or {})
    s.pop("id", None)

    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("服务名称不能为空")
    s["name"] = name
    s["desc"] = (data.get("desc") or "").strip()
    s["icon"] = (data.get("icon") or "").strip()
    s["category"] = (data.get("category") or "").strip() or "应用"

    port = data.get("port", None)
    if port in (None, ""):
        s["port"] = None
    else:
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError("端口必须是数字")
        if not (1 <= port <= 65535):
            raise ValueError("端口范围必须在 1-65535")
        s["port"] = port

    scheme = (data.get("scheme") or "").strip().lower()
    if scheme and scheme not in ("http", "https"):
        raise ValueError("协议只能是 http 或 https")
    s["scheme"] = scheme  # 留空表示按网络默认（port 网络默认 http，domain 网络默认 https）

    s["tunnel"] = bool(data.get("tunnel"))
    domain = (data.get("domain") or "").strip().rstrip("/")
    # 容错：用户可能粘贴了 https://xxx
    domain = domain.replace("https://", "").replace("http://", "")
    s["domain"] = domain

    path = (data.get("path") or "").strip()
    if path and not path.startswith("/"):
        path = "/" + path
    s["path"] = path

    if s["tunnel"] and not domain:
        raise ValueError("勾选“内网穿透”后必须填写域名")
    if not s["port"] and not domain:
        raise ValueError("请至少填写端口（内网/组网可达）或域名（公网可达）")

    # 高级字段：仅在手动编辑 YAML 时使用，按网络覆盖 host / domain
    if isinstance(data.get("hosts"), dict):
        s["hosts"] = data["hosts"]
    if isinstance(data.get("domains"), dict):
        s["domains"] = data["domains"]

    # 去掉空字符串字段，配置更干净
    return {k: v for k, v in s.items() if v not in ("", None) or k in ("port",)}


def clean_network(data, taken_ids):
    """校验并归一化一个网络定义。失败抛 ValueError。"""
    if not isinstance(data, dict):
        raise ValueError("网络格式不正确")

    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("网络名称不能为空")

    mode = (data.get("mode") or "").strip().lower()
    if mode not in ("port", "domain"):
        raise ValueError("网络类型只能是 port 或 domain")

    nid = (data.get("id") or "").strip().lower()
    if not nid:
        nid = secrets.token_hex(3)
    if not all(c.isalnum() or c in "-_" for c in nid):
        raise ValueError("网络 id 只能用字母、数字、- 和 _")
    if nid in taken_ids:
        raise ValueError("网络 id 重复：%s" % nid)

    net = {"id": nid, "name": name, "icon": (data.get("icon") or "").strip(), "mode": mode}

    if mode == "port":
        host = (data.get("host") or "").strip()
        host = host.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        if not host:
            raise ValueError("「%s」是按端口访问的网络，必须填这台机器在该网络下的地址" % name)
        net["host"] = host

    match = data.get("match")
    if isinstance(match, str):
        match = [match]
    match = [str(m).strip() for m in (match or []) if str(m).strip()]
    if not match:
        raise ValueError("「%s」至少要有一条匹配规则" % name)
    net["match"] = match

    return {k: v for k, v in net.items() if v not in ("", None)}


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
_bootstrap = load_config()
app.secret_key = _bootstrap["secret_key"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,  # 30 天
    JSON_AS_ASCII=False,
    # 请求体硬上限，超了 Werkzeug 直接抛 413，不会把文件收完再判断。
    # 除了上传背景，其余接口的请求体都是几 KB 的 JSON，用同一个上限没问题。
    MAX_CONTENT_LENGTH=MAX_UPLOAD,
)


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "文件太大，最大 %d MB" % (MAX_UPLOAD // (1024 * 1024))}), 413


def needs_setup():
    return not load_config().get("password_hash")


def is_authed():
    return bool(session.get("authed"))


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_authed():
            return jsonify({"error": "未登录"}), 401
        return f(*args, **kwargs)
    return wrapper


def require_json(f):
    """轻量 CSRF 缓解：写操作必须是 application/json。"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "请使用 application/json"}), 415
        return f(*args, **kwargs)
    return wrapper


@app.after_request
def no_store(resp):
    """页面和 API 一律不许浏览器缓存。

    渲染出来的 HTML 既依赖会话，又会随每次发版改变。之前这个响应上**一个缓存头
    都没有**（只有 Vary: Cookie），浏览器碰到这种响应会按启发式规则自己缓存一份，
    而且不回源校验 —— 表现出来就是「发了新版，头一次打开是新的，之后又变回旧
    页面」，比如新加的按钮时有时无。

    static/ 下的文件不动：Flask 本来就给它们发 no-cache + ETag，走协商缓存，
    既不会过期也不浪费流量。SSE 那个响应自己已经带了 Cache-Control，这里用
    setdefault 不会覆盖它。
    """
    if resp.mimetype in ("text/html", "application/json"):
        resp.headers.setdefault("Cache-Control", "no-store, must-revalidate")
    return resp


# ---- 页面路由 -------------------------------------------------------------
@app.route("/")
def index():
    if needs_setup():
        return redirect(url_for("setup_page"))
    if not is_authed():
        return redirect(url_for("login_page"))
    return render_template("index.html", title=app_title(load_config()))


@app.route("/login")
def login_page():
    if needs_setup():
        return redirect(url_for("setup_page"))
    if is_authed():
        return redirect(url_for("index"))
    return render_template("auth.html", mode="login", title=app_title(load_config()))


@app.route("/setup")
def setup_page():
    if not needs_setup():
        return redirect(url_for("login_page"))
    return render_template("auth.html", mode="setup", title=app_title(load_config()))


# ---- 认证 API -------------------------------------------------------------
@app.get("/api/status")
def api_status():
    return jsonify({"needs_setup": needs_setup(), "authenticated": is_authed()})


@app.get("/api/pubkey")
def api_pubkey():
    """前端加密密码用的公钥。未登录也要能取（登录本身就需要它）。

    直接给 modulus / 指数，省得前端再解析 DER；ts 是服务端时间，前端拿它当
    信封时间戳，这样客户端时钟不准也不会误判过期。
    """
    numbers = transport_key().public_key().public_numbers()
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    return jsonify({
        "alg": "RSA-OAEP-256",
        "n": base64.b64encode(modulus).decode("ascii"),
        "e": numbers.e,
        "ts": int(time.time() * 1000),
    })


@app.post("/api/setup")
@require_json
def api_setup():
    if not needs_setup():
        return jsonify({"error": "密码已设置"}), 400
    try:
        pw = decrypt_password((request.get_json(silent=True) or {}).get("enc"), "setup").strip()
    except DecryptError as e:
        return jsonify({"error": str(e)}), 400
    if len(pw) < 6:
        return jsonify({"error": "密码至少 6 位"}), 400
    cfg = load_config()
    cfg["password_hash"] = generate_password_hash(pw)
    save_config(cfg)
    session.permanent = True
    session["authed"] = True
    return jsonify({"ok": True})


@app.post("/api/login")
@require_json
def api_login():
    try:
        pw = decrypt_password((request.get_json(silent=True) or {}).get("enc"), "login")
    except DecryptError as e:
        return jsonify({"error": str(e)}), 400
    cfg = load_config()
    if cfg.get("password_hash") and check_password_hash(cfg["password_hash"], pw):
        session.permanent = True
        session["authed"] = True
        return jsonify({"ok": True})
    return jsonify({"error": "密码错误"}), 401


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/password")
@login_required
@require_json
def api_password():
    data = request.get_json(silent=True) or {}
    try:
        cur = decrypt_password(data.get("current"), "current")
        new = decrypt_password(data.get("new"), "new").strip()
    except DecryptError as e:
        return jsonify({"error": str(e)}), 400
    cfg = load_config()
    if not check_password_hash(cfg.get("password_hash", ""), cur):
        return jsonify({"error": "当前密码不正确"}), 400
    if len(new) < 6:
        return jsonify({"error": "新密码至少 6 位"}), 400
    cfg["password_hash"] = generate_password_hash(new)
    save_config(cfg)
    return jsonify({"ok": True})


# ---- 配置 / 服务 API ------------------------------------------------------
@app.get("/api/config")
@login_required
def api_config():
    return jsonify(public_config(load_config()))


@app.put("/api/networks")
@login_required
@require_json
def api_set_networks():
    """整份替换 networks。首次引导和以后改网络都走这里。

    整份替换而不是逐条增删，是因为 networks 的**顺序**本身就是语义
    （匹配时从上往下，第一个命中的生效），逐条改反而容易把顺序搞乱。
    """
    data = request.get_json(silent=True) or {}
    items = data.get("networks")
    if not isinstance(items, list) or not items:
        return jsonify({"error": "至少要配置一个网络"}), 400
    if len(items) > 12:
        return jsonify({"error": "网络最多 12 个"}), 400

    cleaned, ids = [], set()
    try:
        for item in items:
            net = clean_network(item, ids)
            ids.add(net["id"])
            cleaned.append(net)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    cfg = load_config()
    cfg["networks"] = cleaned
    save_config(cfg)
    return jsonify(public_config(cfg))


@app.post("/api/services")
@login_required
@require_json
def api_add_service():
    data = request.get_json(silent=True) or {}
    try:
        fields = clean_service(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    cfg = load_config()
    fields["id"] = secrets.token_hex(4)
    cfg["services"].append(fields)
    save_config(cfg)
    return jsonify(public_config(cfg))


@app.put("/api/services/<sid>")
@login_required
@require_json
def api_update_service(sid):
    data = request.get_json(silent=True) or {}
    cfg = load_config()
    idx = next((i for i, s in enumerate(cfg["services"]) if s.get("id") == sid), None)
    if idx is None:
        return jsonify({"error": "服务不存在"}), 404
    try:
        fields = clean_service(data, existing=cfg["services"][idx])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    fields["id"] = sid
    cfg["services"][idx] = fields
    save_config(cfg)
    return jsonify(public_config(cfg))


@app.delete("/api/services/<sid>")
@login_required
def api_delete_service(sid):
    cfg = load_config()
    before = len(cfg["services"])
    cfg["services"] = [s for s in cfg["services"] if s.get("id") != sid]
    if len(cfg["services"]) == before:
        return jsonify({"error": "服务不存在"}), 404
    save_config(cfg)
    return jsonify(public_config(cfg))


# ---------------------------------------------------------------------------
# 服务健康检查
# ---------------------------------------------------------------------------
# 只是 TCP connect 一下就关掉，不发任何数据。所以判断的是「端口通不通」，
# 不是「服务是否正常」—— 反代后面的域名探 443 通，只说明反代活着。
HEALTH_TIMEOUT = 1.5
HEALTH_WORKERS = 32

# 哨兵探测：判断一个地址是不是「什么端口都通」。
#
# 组网 / VPN 那类用户态 TUN 协议栈（本机上是 NodeBabyLink）会替任意端口完成 TCP
# 握手，对着这种地址做连通性探测，结果永远是通 —— 一排假绿比没有状态还糟。
# 打几个随机高位端口，全通就判这个地址不可信，改从别的网络借地址来探。
SENTINEL_PORTS = 3
SENTINEL_TTL = 300           # 判定结果缓存多久（秒）
_sentinel_cache = {}         # host -> (可信?, 过期时间戳)


def _tcp_open(host, port, timeout=HEALTH_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _host_trustworthy(host):
    """这个地址的探测结果可不可信。带 5 分钟缓存，免得每轮轮询都重打一遍。

    多 worker 下每个进程各存一份，无所谓 —— 这只是省几个连接的优化，
    算错了最坏也就是多探一次。
    """
    now = time.time()
    hit = _sentinel_cache.get(host)
    if hit and hit[1] > now:
        return hit[0]
    picks = random.sample(range(49152, 65500), SENTINEL_PORTS)
    with ThreadPoolExecutor(max_workers=SENTINEL_PORTS) as ex:
        opened = sum(ex.map(lambda p: _tcp_open(host, p, HEALTH_TIMEOUT), picks))
    # 随机高位端口全通 = 这地址对谁都说通
    trusted = opened < SENTINEL_PORTS
    _sentinel_cache[host] = (trusted, now + SENTINEL_TTL)
    return trusted


def _health_target(svc, net):
    """算出这个服务在指定网络下该探哪个 host:port，口径跟前端 resolveUrl 一致。"""
    if not net:
        return None
    if net.get("mode") == "domain":
        domain = (svc.get("domains") or {}).get(net["id"]) or svc.get("domain")
        if not domain:
            return None
        return domain, 443 if (svc.get("scheme") or "https") == "https" else 80
    host = (svc.get("hosts") or {}).get(net["id"]) or net.get("host")
    port = svc.get("port")
    if not host or not port:
        return None
    return host, port


def _pick_probe(svc, view, networks):
    """给一个服务挑「从哪儿探」，返回 (host, port, 借用的网络名 or None)。

    先用当前视角这个网络的地址。它要是不可信（哨兵判定「什么端口都通」），
    才按 networks 的顺序借一个可信网络的地址 —— 各网络指向的是同一台机器，
    「端口通不通」是同一件事，只是那条路不会撒谎。借了就把网络名带回去，
    前端在悬浮提示里写明，不含糊。

    但「当前网络下解析不出地址」不借：那说明这个服务在这个网络下**本来就到不了**
    （比如没给它配公网域名），不是探不准。这时候借内网地址探出一个绿点，等于凭空
    编了个「公网可达」出来。该给灰点就给灰点。
    """
    direct = _health_target(svc, view)
    if not direct:
        return None
    if _target_trustworthy(view, direct):
        return direct[0], direct[1], None
    for net in networks:
        if not view or net.get("id") == view.get("id"):
            continue
        t = _health_target(svc, net)
        if t and _target_trustworthy(net, t):
            return t[0], t[1], net.get("name") or net.get("id")
    return None


def _target_trustworthy(net, target):
    """域名一律当可信：反代能应 443 本身就是有意义的信号，
    而且逐个域名打哨兵既慢又容易被当成扫描。只对端口模式的主机做判定。"""
    if not net or net.get("mode") == "domain":
        return True
    return _host_trustworthy(target[0])


@app.get("/api/health")
@login_required
def api_health():
    """探测各服务的连通性。

    返回 {"states": {服务id: up|down|unknown}, "via": {服务id: 借用的网络名}}。

    在当前网络下解析不出地址的服务（没配 host / 没配域名）是 unknown，
    而不是 down —— 那是「没配」，不是「挂了」。
    """
    cfg = load_config()
    networks = cfg.get("networks") or []
    net_id = request.args.get("network") or ""
    view = next((n for n in networks if n.get("id") == net_id), None)
    services = [s for s in (cfg.get("services") or []) if s.get("id")]

    states = {s["id"]: "unknown" for s in services}
    via = {}
    targets = {}
    for s in services:
        pick = _pick_probe(s, view, networks)
        if pick:
            targets[s["id"]] = (pick[0], pick[1])
            if pick[2]:
                via[s["id"]] = pick[2]
    if not targets:
        return jsonify({"states": states, "via": via})

    with ThreadPoolExecutor(max_workers=min(HEALTH_WORKERS, len(targets))) as ex:
        futures = {ex.submit(_tcp_open, h, p): sid for sid, (h, p) in targets.items()}
        for fut, sid in futures.items():
            states[sid] = "up" if fut.result() else "down"
    return jsonify({"states": states, "via": via})


# ---------------------------------------------------------------------------
# 自定义背景
# ---------------------------------------------------------------------------
def _drop_backgrounds(keep=None):
    """删掉除 keep 以外的所有背景文件。

    换背景时后缀可能变（jpg -> mp4），不清理的话旧文件会一直躺在 uploads 里。

    删不掉就算了：Windows 上如果这个文件恰好还在被某个响应读着，remove 会失败。
    残留的文件已经没人引用，下次传同后缀的图会直接覆盖掉，不值得为它重试。
    """
    for ext in BG_EXT:
        name = BG_STEM + "." + ext
        if name == keep:
            continue
        try:
            os.remove(os.path.join(UPLOAD_DIR, name))
        except OSError:
            pass


@app.get("/bg/<name>")
@login_required
def serve_background(name):
    """发 data/uploads 里的背景文件。

    static/ 是 Flask 自己管的镜像内目录，这份要单开一个路由，因为文件在挂载卷上。
    """
    if not safe_bg_name(name):
        return jsonify({"error": "无效的文件名"}), 404
    resp = send_from_directory(UPLOAD_DIR, name)
    # 用户上传的文件从本站域名发出，钉死 Content-Type，不让浏览器嗅探
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # URL 上带了 mtime 版本号，可以放心让浏览器缓存
    resp.headers["Cache-Control"] = "private, max-age=86400"
    return resp


@app.post("/api/background")
@login_required
def api_set_background():
    """上传背景图 / 视频。

    这个接口是 multipart 的，用不了 require_json 那道 CSRF 缓解；实际挡住跨站
    提交的是 SESSION_COOKIE_SAMESITE="Lax" —— 跨站 POST 根本带不上会话 cookie。
    """
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "请选择要上传的文件"}), 400
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in BG_EXT:
        return jsonify({"error": "只支持图片 (jpg/png/webp/gif) 或视频 (mp4/webm)"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    name = BG_STEM + "." + ext
    # 先落临时文件再 rename：传到一半断了不会把正在用的背景弄坏
    tmp = os.path.join(UPLOAD_DIR, name + ".tmp")
    f.save(tmp)
    os.replace(tmp, os.path.join(UPLOAD_DIR, name))
    _drop_backgrounds(keep=name)

    cfg = load_config()
    cfg["background"] = {
        "type": "image" if ext in BG_IMAGE_EXT else "video",
        "file": name,
    }
    save_config(cfg)
    return jsonify(public_config(cfg))


@app.post("/api/background/reset")
@login_required
@require_json
def api_reset_background():
    _drop_backgrounds()
    cfg = load_config()
    cfg["background"] = None
    save_config(cfg)
    return jsonify(public_config(cfg))


# ---------------------------------------------------------------------------
# 端口发现
# ---------------------------------------------------------------------------
# 扫描可能要几十秒，用 SSE 把进度和结果边跑边推给浏览器：
#   - 不会因为反代的 60 秒读超时把整个请求掐断
#   - 前端能一边扫一边出结果，不用干等
# 没做成“提交任务 + 轮询”是因为 gunicorn 多 worker 是多进程，
# A worker 起的任务 B worker 看不见，轮询会随机查不到。
def _clamp(v, lo, hi):
    try:
        v = float(v)
    except (TypeError, ValueError):
        v = lo
    return max(lo, min(hi, v))


def _discover_allowed(host, ip, cfg):
    """限制扫描目标：默认只放行内网，外加配置里已经出现过的主机 / 域名。

    这个接口虽然要登录，但放任它扫任意公网地址就等于给自己开了个代理扫描器，
    没必要。真要扫外面，把 config.yaml 里 discover.allow_public 打开。
    """
    if discover.is_private_target(ip):
        return True
    if (cfg.get("discover") or {}).get("allow_public"):
        return True

    known = set()
    for net in cfg.get("networks", []) or []:
        if net.get("host"):
            known.add(str(net["host"]).lower())
    for svc in cfg.get("services", []) or []:
        if svc.get("domain"):
            known.add(str(svc["domain"]).lower())
        for v in (svc.get("domains") or {}).values():
            known.add(str(v).lower())
        for v in (svc.get("hosts") or {}).values():
            known.add(str(v).lower())
    return (host or "").lower() in known


@app.post("/api/discover")
@login_required
@require_json
def api_discover():
    cfg = load_config()
    data = request.get_json(silent=True) or {}
    defaults = cfg.get("discover") or {}

    host = (data.get("host") or "").strip()
    if not host:
        net = next((n for n in cfg.get("networks", []) or [] if n.get("host")), None)
        host = (net or {}).get("host", "")
    try:
        ip, family = discover.resolve_target(host)
        ports = discover.parse_ports(data.get("ports"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not _discover_allowed(host, ip, cfg):
        return jsonify({"error": "%s 不是内网地址，也不在已配置的主机里。"
                                 "如需扫描外部地址，请把 config.yaml 中的 "
                                 "discover.allow_public 改成 true" % ip}), 403

    timeout = _clamp(data.get("timeout") or defaults.get("timeout", 0.4), 0.05, 5.0)
    concurrency = int(_clamp(data.get("concurrency") or defaults.get("concurrency", 256),
                             8, discover.MAX_CONCURRENCY))

    def stream():
        try:
            for ev in discover.run(host, ip, family, ports,
                                   timeout=timeout, concurrency=concurrency):
                yield "data: %s\n\n" % json.dumps(ev, ensure_ascii=False)
        except GeneratorExit:          # 浏览器中途关掉了连接
            raise
        except Exception as e:
            yield "data: %s\n\n" % json.dumps(
                {"type": "error", "message": "扫描出错：%s" % e}, ensure_ascii=False)

    return Response(stream(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",     # 让 nginx 别缓冲，否则进度会一次性到达
        "Connection": "keep-alive",
    })


# ---------------------------------------------------------------------------
# 命令行：设置 / 重置密码
# ---------------------------------------------------------------------------
def cli_setpw():
    import getpass
    cfg = load_config()
    p1 = getpass.getpass("设置访问密码: ")
    p2 = getpass.getpass("再次输入确认: ")
    if p1 != p2:
        print("✗ 两次输入不一致"); sys.exit(1)
    if len(p1) < 6:
        print("✗ 密码至少 6 位"); sys.exit(1)
    cfg["password_hash"] = generate_password_hash(p1)
    save_config(cfg)
    print(f"✓ 密码已加密保存到 {CONFIG_PATH}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("setpw", "--setpw", "passwd", "password"):
        cli_setpw()
    else:
        app.run(
            host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "5000")),
            debug=bool(os.environ.get("DEBUG")),
        )
