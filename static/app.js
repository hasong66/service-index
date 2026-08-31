// ============================================================
//  服务索引 · 前端逻辑
// ============================================================
(function () {
  "use strict";

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const STATE = {
    title: "服务索引",
    networks: [],
    services: [],
    detected: null, // 服务端提示
    host: "",
    view: null,     // 当前“视角”网络（卡片主点击使用）
    filter: "all",
    query: "",
    health: {},      // 服务id -> up | down | unknown
    healthVia: {},   // 服务id -> 借用了哪个网络的地址去探（当前网络不可信时）
    background: null,  // null = 用主题自带的渐变底
  };

  // ---------- 工具 ----------
  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  let toastTimer;
  function toast(msg, type) {
    const t = $("#toast");
    t.textContent = msg;
    t.className = "toast show " + (type || "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.className = "toast " + (type || "")), 2600);
  }

  async function api(method, url, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    const res = await fetch(url, opt);
    if (res.status === 401) {
      location.href = "/login";
      throw new Error("unauthorized");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "HTTP " + res.status);
    return data;
  }

  // ---------- 网络匹配 / 地址解析 ----------
  function matchHost(hostname, pattern) {
    hostname = (hostname || "").toLowerCase();
    pattern = (pattern || "").toLowerCase();
    if (!pattern) return false;
    if (pattern === hostname) return true;
    if (pattern.startsWith("*.")) return hostname.endsWith(pattern.slice(1)); // *.example.com
    if (pattern.endsWith("*")) return hostname.startsWith(pattern.slice(0, -1)); // 192.168.* / 10.*
    return false;
  }

  // 以浏览器地址栏 hostname 为准识别当前网络
  function detectNetwork() {
    const h = location.hostname.toLowerCase();
    for (const net of STATE.networks) {
      for (const p of net.match || []) {
        if (matchHost(h, p)) return net.id;
      }
    }
    return STATE.networks.length ? STATE.networks[0].id : null;
  }

  const netById = (id) => STATE.networks.find((n) => n.id === id);

  function normPath(p) {
    if (!p) return "";
    return p.startsWith("/") ? p : "/" + p;
  }

  // 给定服务 + 网络，算出可跳转的完整 URL；不可达返回 null
  function resolveUrl(svc, networkId) {
    const net = netById(networkId);
    if (!net) return null;
    if (net.mode === "domain") {
      const domain = (svc.domains && svc.domains[networkId]) || svc.domain;
      if (!domain) return null;
      const scheme = svc.scheme || "https";
      return scheme + "://" + domain + normPath(svc.path);
    } else {
      const host = (svc.hosts && svc.hosts[networkId]) || net.host;
      if (!host || !svc.port) return null;
      const scheme = svc.scheme || "http";
      return scheme + "://" + host + ":" + svc.port + normPath(svc.path);
    }
  }

  // 把 URL 拆成 scheme + 其余，便于上色显示
  function splitUrl(url) {
    const m = /^(https?:\/\/)(.*)$/.exec(url);
    return m ? { scheme: m[1], rest: m[2] } : { scheme: "", rest: url };
  }

  // ---------- 头像配色 ----------
  function hue(str) {
    let h = 0;
    for (const c of String(str)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return h % 360;
  }
  function avatarHtml(svc) {
    if (svc.icon) return `<div class="avatar" style="${avatarStyle(svc.name)}">${escapeHtml(svc.icon)}</div>`;
    const ch = (svc.name || "?").trim().charAt(0).toUpperCase();
    return `<div class="avatar txt" style="${avatarStyle(svc.name)}">${escapeHtml(ch)}</div>`;
  }
  function avatarStyle(seed) {
    const h = hue(seed);
    return `background:hsl(${h} 42% 17%);color:hsl(${h} 72% 68%)`;
  }

  // ---------- 背景 ----------
  function renderBackground() {
    const root = $("#bg-root");
    if (!root) return;
    const bg = STATE.background;
    // 有自定义背景时，一部分文字要加深才看得清 —— 用这个类去开那批样式，
    // 而不是无条件加深（没背景时纯属丑化）。
    document.body.classList.toggle("has-bg", !!bg);
    if (!bg) { root.innerHTML = ""; return; }
    if (bg.type === "image") {
      root.innerHTML = `<img class="bg-media" src="${escapeHtml(bg.url)}" alt="">`;
      return;
    }
    // type 必须跟实际格式对上：写死 video/mp4 的话，传 webm 会直接播不出来
    root.innerHTML =
      `<video class="bg-media" autoplay muted loop playsinline>
         <source src="${escapeHtml(bg.url)}" type="${escapeHtml(bg.mime || "video/mp4")}">
       </video>`;
  }

  async function uploadBackground(file) {
    const fd = new FormData();
    fd.append("file", file);
    try {
      // 这里不能走 api()：那个函数固定发 JSON，上传得用 multipart
      const res = await fetch("/api/background", { method: "POST", body: fd });
      if (res.status === 401) { location.href = "/login"; return; }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "上传失败");
      applyConfig(data);
      closeOverlay("#bg-overlay");
      toast("背景已更新", "ok");
    } catch (e) {
      toast(e.message || "上传失败", "err");
    }
  }

  async function resetBackground() {
    try {
      applyConfig(await api("POST", "/api/background/reset", {}));
      closeOverlay("#bg-overlay");
      toast("已恢复默认背景", "ok");
    } catch (e) {
      toast(e.message, "err");
    }
  }

  // ============================================================
  //  渲染
  // ============================================================
  function render() {
    renderNetSwitch();
    renderAccessInfo();
    renderChips();
    renderGrid();
  }

  function renderNetSwitch() {
    const box = $("#net-switch");
    box.innerHTML = STATE.networks
      .map((n) => {
        const active = n.id === STATE.view ? " active" : "";
        const detected = n.id === STATE.detected
          ? `<span class="detect-dot" title="当前识别到的网络"></span>` : "";
        return `<button class="net-tab${active}" data-net="${escapeHtml(n.id)}">
                  <span class="ico">${escapeHtml(n.icon || "•")}</span>${escapeHtml(n.name)}${detected}
                </button>`;
      })
      .join("");
  }

  function renderAccessInfo() {
    const net = netById(STATE.detected);
    $("#access-info").innerHTML =
      `<span>正通过 <span class="host">${escapeHtml(location.host)}</span> 访问</span>` +
      `<span>·</span>` +
      `<span>识别为 <b>${net ? escapeHtml(net.icon + " " + net.name) : "未知"}</b></span>`;
  }

  function categories() {
    const seen = [];
    for (const s of STATE.services) {
      const c = s.category || "应用";
      if (!seen.includes(c)) seen.push(c);
    }
    return seen;
  }

  function renderChips() {
    const cats = categories();
    const datalist = $("#cat-list");
    if (datalist) datalist.innerHTML = cats.map((c) => `<option value="${escapeHtml(c)}">`).join("");

    const chip = (id, label) =>
      `<button class="chip${STATE.filter === id ? " active" : ""}" data-chip="${escapeHtml(id)}">${escapeHtml(label)}</button>`;
    $("#chips").innerHTML =
      chip("all", `全部 ${STATE.services.length}`) + cats.map((c) => chip(c, c)).join("");
  }

  function matchQuery(svc) {
    const q = STATE.query.trim().toLowerCase();
    if (!q) return true;
    const hay = [svc.name, svc.desc, svc.category, svc.domain, svc.port, svc.path]
      .filter(Boolean).join(" ").toLowerCase();
    return hay.includes(q);
  }

  function renderGrid() {
    const root = $("#grid-root");
    let list = STATE.services.filter(matchQuery);
    if (STATE.filter !== "all") list = list.filter((s) => (s.category || "应用") === STATE.filter);

    if (!list.length) {
      root.innerHTML = "";
      const blank = !STATE.services.length;
      $("#empty-title").textContent = blank ? "还没有服务" : "还没有匹配的服务";
      $("#empty-sub").textContent = blank
        ? "点右上角「＋ 添加服务」手动加，或者用 🔍 端口发现扫一遍这台机器自动找出来"
        : "换个搜索词，或点「全部」取消筛选";
      $("#empty").hidden = false;
      return;
    }
    $("#empty").hidden = true;

    // 分组
    const order = [];
    const byCat = {};
    for (const s of list) {
      const c = s.category || "应用";
      if (!byCat[c]) { byCat[c] = []; order.push(c); }
      byCat[c].push(s);
    }

    let i = 0;
    root.innerHTML = order
      .map((cat) => {
        const cards = byCat[cat].map((s) => cardHtml(s, i++)).join("");
        return `<section class="cat">
                  <h2 class="cat-title">${escapeHtml(cat)}<span class="count">${byCat[cat].length}</span></h2>
                  <div class="cards">${cards}</div>
                </section>`;
      })
      .join("");
  }

  const HEALTH_TITLE = { up: "运行中", down: "已离线", unknown: "状态未知" };

  /** 悬浮提示。借了别的网络的地址探测时说清楚，别让人以为探的是当前这个。 */
  function healthTitle(id) {
    const t = HEALTH_TITLE[STATE.health[id] || "unknown"];
    const via = STATE.healthVia[id];
    return via ? t + "（当前网络的地址探不出真假，此处探测自「" + via + "」）" : t;
  }

  function cardHtml(svc, idx) {
    const url = resolveUrl(svc, STATE.view);
    const reachable = !!url;
    // 从 STATE 读而不是写死 unknown：render() 在搜索 / 切分类 / 切网络时都会
    // 重建卡片，写死的话每次重建状态点都会先灭一轮。
    const health = STATE.health[svc.id] || "unknown";

    // 主体（可达 -> a，不可达 -> div）
    let addr;
    if (reachable) {
      const sp = splitUrl(url);
      addr = `<div class="addr"><span class="scheme">${sp.scheme}</span>${escapeHtml(sp.rest)}</div>`;
    } else {
      addr = `<div class="addr na">· 当前网络不可达 ·</div>`;
    }
    const inner =
      `${avatarHtml(svc)}
       <div class="meta">
         <div class="name">${escapeHtml(svc.name)}</div>
         ${svc.desc ? `<div class="desc">${escapeHtml(svc.desc)}</div>` : ""}
         ${addr}
       </div>`;
    const main = reachable
      ? `<a class="card-main" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${inner}</a>`
      : `<div class="card-main">${inner}</div>`;

    // 各网络可达徽标
    const pills = STATE.networks
      .map((n) => {
        const u = resolveUrl(svc, n.id);
        const active = n.id === STATE.view ? " active" : "";
        if (u) {
          return `<a class="net-pill${active}" href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer"
                     title="${escapeHtml(u)}"><span class="ico">${escapeHtml(n.icon || "•")}</span>${escapeHtml(n.name)}</a>`;
        }
        return `<span class="net-pill dead" title="未配置"><span class="ico">${escapeHtml(n.icon || "•")}</span>${escapeHtml(n.name)}</span>`;
      })
      .join("");

    return `<div class="card${reachable ? "" : " off"}" style="--i:${idx}" data-id="${escapeHtml(svc.id)}">
              <span class="status-dot ${health}" data-role="status" title="${escapeHtml(healthTitle(svc.id))}"></span>
              ${main}
              <div class="card-nets">${pills}</div>
              <div class="card-tools">
                <button class="icon-btn" data-action="edit" data-id="${escapeHtml(svc.id)}" title="编辑">✎</button>
                <button class="icon-btn del" data-action="del" data-id="${escapeHtml(svc.id)}" title="删除">🗑</button>
              </div>
            </div>`;
  }

  // ============================================================
  //  服务表单（添加 / 编辑）
  // ============================================================
  // svc 带 id -> 编辑；不带 id 的对象 -> 新建但预填（端口发现过来的就是这种）
  function openServiceModal(svc) {
    const s = svc || {};
    const editing = !!s.id;
    $("#svc-modal-title").textContent = editing ? "编辑服务" : "添加服务";
    $("#f-id").value = editing ? s.id : "";
    $("#f-name").value = s.name || "";
    $("#f-icon").value = s.icon || "";
    $("#f-desc").value = s.desc || "";
    $("#f-category").value = s.category || "";
    $("#f-port").value = s.port || "";
    $("#f-scheme").value = s.scheme || "";
    $("#f-tunnel").checked = !!s.tunnel;
    $("#f-domain").value = s.domain || "";
    $("#f-path").value = s.path || "";
    syncTunnel();
    // 高级区：有 path 时默认展开
    setAdv(!!s.path);
    hideErr("#svc-err");
    openOverlay("#svc-overlay");
    setTimeout(() => $("#f-name").focus(), 50);
  }

  function syncTunnel() {
    const on = $("#f-tunnel").checked;
    $("#tunnel-check").classList.toggle("on", on);
    $("#domain-field").dataset.collapsed = on ? "false" : "true";
  }

  function setAdv(open) {
    $("#adv-section").dataset.collapsed = open ? "false" : "true";
    $("#adv-toggle").textContent = (open ? "▾" : "▸") + " 高级选项";
  }

  async function saveService() {
    const payload = {
      name: $("#f-name").value,
      icon: $("#f-icon").value,
      desc: $("#f-desc").value,
      category: $("#f-category").value,
      port: $("#f-port").value,
      scheme: $("#f-scheme").value,
      tunnel: $("#f-tunnel").checked,
      domain: $("#f-domain").value,
      path: $("#f-path").value,
    };
    const id = $("#f-id").value;
    const btn = $("#svc-save");
    btn.disabled = true;
    hideErr("#svc-err");
    try {
      const data = id
        ? await api("PUT", "/api/services/" + id, payload)
        : await api("POST", "/api/services", payload);
      applyConfig(data);
      closeOverlay("#svc-overlay");
      toast(id ? "已更新" : "已添加", "ok");
    } catch (e) {
      showErr("#svc-err", e.message);
    } finally {
      btn.disabled = false;
    }
  }

  async function deleteService(id) {
    const svc = STATE.services.find((s) => s.id === id);
    if (!svc) return;
    if (!confirm(`删除服务「${svc.name}」？`)) return;
    try {
      const data = await api("DELETE", "/api/services/" + id);
      applyConfig(data);
      toast("已删除", "ok");
    } catch (e) {
      toast(e.message, "err");
    }
  }

  // ============================================================
  //  修改密码
  // ============================================================
  async function changePassword() {
    const cur = $("#pw-cur").value;
    const nw = $("#pw-new").value;
    const nw2 = $("#pw-new2").value;
    hideErr("#pw-err");
    if (nw.length < 6) return showErr("#pw-err", "新密码至少 6 位");
    if (nw !== nw2) return showErr("#pw-err", "两次输入不一致");
    const btn = $("#pw-save");
    btn.disabled = true;
    try {
      // 两个密码各自加密成一个信封，明文不进请求体
      const enc = await PwCrypto.encrypt({ current: cur, new: nw });
      await api("POST", "/api/password", { current: enc.current, new: enc.new });
      closeOverlay("#pw-overlay");
      toast("密码已更新", "ok");
    } catch (e) {
      showErr("#pw-err", e.message);
    } finally {
      btn.disabled = false;
    }
  }

  // ============================================================
  //  首次引导：配置网络
  // ============================================================
  // networks 为空时（全新部署）不显示服务网格，先让用户把网络定义出来 ——
  // 没有网络，服务的地址就无从拼起，整个页面是空转的。
  // 第一个网络由服务端根据"你此刻用什么地址打开的这个页面"预填好（见 app.py
  // 的 suggest_network），多数人只需要点一下"完成"。
  const WIZ = { rows: [], suggest: null };

  const NET_TEMPLATES = {
    lan:    { name: "内网",   icon: "🏠", mode: "port",   host: "", match: "192.168.1.*" },
    mesh:   { name: "组网",   icon: "🛰️", mode: "port",   host: "", match: "10.*" },
    public: { name: "公网",   icon: "🌐", mode: "domain", host: "", match: "*.example.com" },
  };

  function startWizard(data) {
    WIZ.suggest = data.suggest || null;
    if (!WIZ.rows.length) {
      const s = WIZ.suggest;
      WIZ.rows = [s
        ? { id: s.id, name: s.name, icon: s.icon, mode: s.mode,
            host: s.host || "", match: (s.match || []).join(", "), fromServer: true }
        : Object.assign({ id: "lan" }, NET_TEMPLATES.lan)];
    }
    // 引导阶段顶栏没有意义（还没有网络可切、没有服务可搜），整条藏掉
    $(".topbar").hidden = true;
    $("#wizard").hidden = false;
    $("#main-view").hidden = true;

    const host = escapeHtml(data.host || location.hostname);
    const core = "这个索引的核心是<b>「你从哪个地址打开它，就跳到哪个地址的服务」</b>。<br>所以得先知道你有哪几个网络。";
    // 猜得出就照实说猜出来了；猜不出（比如你正用 localhost 访问）也照实说，
    // 别让页面写着"已经填好了"而输入框其实是空的
    $("#wiz-lead").innerHTML = core + (WIZ.suggest
      ? `你现在是通过 <span class="mono">${host}</span> 打开的，第一个网络已经照着它填好了，确认无误就可以直接保存。`
      : `你现在通过 <span class="mono">${host}</span> 访问，这个地址看不出你的网段，所以下面要你自己填一下 —— 填这台机器在局域网里的地址就行。`);
    renderWizard();
  }

  function finishWizard() {
    $(".topbar").hidden = false;
    $("#wizard").hidden = true;
    $("#main-view").hidden = false;
  }

  function renderWizard() {
    $("#wiz-rows").innerHTML = WIZ.rows
      .map((r, i) => {
        const isPort = r.mode === "port";
        return `<div class="wiz-net" data-i="${i}">
          <div class="wiz-net-head">
            <input class="wiz-icon mono" data-f="icon" value="${escapeHtml(r.icon || "")}" maxlength="4" placeholder="🏠">
            <input class="wiz-name" data-f="name" value="${escapeHtml(r.name || "")}" placeholder="网络名，如 内网">
            <select class="wiz-mode" data-f="mode">
              <option value="port"${isPort ? " selected" : ""}>按端口访问</option>
              <option value="domain"${isPort ? "" : " selected"}>按域名访问</option>
            </select>
            ${WIZ.rows.length > 1 ? `<button class="icon-btn del" data-wiz-del="${i}" title="删掉这个网络">🗑</button>` : ""}
          </div>
          <div class="wiz-net-body">
            <label>${isPort
              ? `这台机器在该网络下的地址 <span class="hint">服务的地址 = 它 : 服务端口</span>`
              : `<span class="hint">域名模式下地址来自每个服务自己的域名，这里不用填主机</span>`}</label>
            ${isPort
              ? `<input class="mono" data-f="host" value="${escapeHtml(r.host || "")}" placeholder="192.168.1.50">`
              : ""}
            <label>命中规则 <span class="hint">你用什么地址打开索引页时算作这个网络；逗号分隔，支持 192.168.* 和 *.example.com</span></label>
            <input class="mono" data-f="match" value="${escapeHtml(r.match || "")}" placeholder="192.168.*">
          </div>
        </div>`;
      })
      .join("");
    $("#wiz-count").textContent = WIZ.rows.length + " 个网络";
  }

  function readWizardRows() {
    $$("#wiz-rows .wiz-net").forEach((el) => {
      const r = WIZ.rows[+el.dataset.i];
      if (!r) return;
      el.querySelectorAll("[data-f]").forEach((inp) => { r[inp.dataset.f] = inp.value; });
    });
  }

  function addWizardRow(kind) {
    readWizardRows();
    const t = NET_TEMPLATES[kind] || NET_TEMPLATES.lan;
    const used = WIZ.rows.map((r) => r.id);
    let id = kind;
    let n = 2;
    while (used.includes(id)) id = kind + n++;
    WIZ.rows.push(Object.assign({ id: id }, t));
    renderWizard();
  }

  async function saveWizard() {
    readWizardRows();
    hideErr("#wiz-err");
    const payload = WIZ.rows.map((r) => ({
      id: r.id,
      name: (r.name || "").trim(),
      icon: (r.icon || "").trim(),
      mode: r.mode,
      host: r.mode === "port" ? (r.host || "").trim() : "",
      match: (r.match || "").split(/[,，\s]+/).filter(Boolean),
    }));
    const btn = $("#wiz-save");
    btn.disabled = true;
    try {
      const data = await api("PUT", "/api/networks", { networks: payload });
      applyConfig(data);
      toast("网络已保存，现在可以添加服务了", "ok");
    } catch (e) {
      showErr("#wiz-err", e.message);
    } finally {
      btn.disabled = false;
    }
  }

  // ---------- 通用 modal / err ----------
  function openOverlay(sel) { $(sel).classList.add("open"); }
  function closeOverlay(sel) { $(sel).classList.remove("open"); }
  function showErr(sel, msg) { const e = $(sel); e.textContent = msg; e.classList.add("show"); }
  function hideErr(sel) { const e = $(sel); e.textContent = ""; e.classList.remove("show"); }

  // ---------- 应用配置 ----------
  function applyConfig(data) {
    STATE.title = data.title || "服务索引";
    STATE.networks = data.networks || [];
    STATE.services = data.services || [];
    STATE.detected = data.detected;
    STATE.host = data.host;
    STATE.background = data.background || null;

    document.title = STATE.title;
    $("#app-title").textContent = STATE.title;
    renderBackground();

    if (data.needs_networks) {
      startWizard(data);
      return;
    }
    finishWizard(data);

    const clientDetected = detectNetwork();
    STATE.detected = clientDetected || data.detected;
    if (!STATE.view || !netById(STATE.view)) STATE.view = STATE.detected;
    render();
    refreshHealth();
    startHealthPolling();
  }

  // ============================================================
  //  事件绑定
  // ============================================================
  function bind() {
    // 搜索
    $("#q").addEventListener("input", (e) => { STATE.query = e.target.value; renderGrid(); });

    // 顶栏按钮
    $("#btn-add").addEventListener("click", () => openServiceModal(null));
    $("#btn-logout").addEventListener("click", async () => {
      await api("POST", "/api/logout").catch(() => {});
      location.href = "/login";
    });
    $("#btn-discover").addEventListener("click", openDiscover);
    $("#btn-bg").addEventListener("click", () => {
      $("#bg-reset").disabled = !STATE.background;
      openOverlay("#bg-overlay");
    });
    $("#bg-pick").addEventListener("click", () => $("#bg-file-input").click());
    $("#bg-reset").addEventListener("click", resetBackground);
    $("#bg-file-input").addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      await uploadBackground(file);
      e.target.value = "";   // 传同一个文件两次也要能触发 change
    });
    $("#btn-settings").addEventListener("click", () => {
      $("#pw-cur").value = $("#pw-new").value = $("#pw-new2").value = "";
      hideErr("#pw-err");
      openOverlay("#pw-overlay");
    });

    // 网络切换 + 分类筛选（事件委托）
    $("#net-switch").addEventListener("click", (e) => {
      const b = e.target.closest("[data-net]");
      if (!b) return;
      STATE.view = b.dataset.net;
      render();
      refreshHealth();
    });
    $("#chips").addEventListener("click", (e) => {
      const b = e.target.closest("[data-chip]");
      if (!b) return;
      STATE.filter = b.dataset.chip;
      renderChips();
      renderGrid();
    });

    // 卡片上的编辑 / 删除
    $("#grid-root").addEventListener("click", (e) => {
      const b = e.target.closest("[data-action]");
      if (!b) return;
      e.preventDefault();
      const svc = STATE.services.find((s) => s.id === b.dataset.id);
      if (b.dataset.action === "edit") openServiceModal(svc);
      else deleteService(b.dataset.id);
    });

    // 表单交互
    $("#f-tunnel").addEventListener("change", syncTunnel);
    $("#tunnel-check").addEventListener("keydown", (e) => {
      if (e.key === " " || e.key === "Enter") { e.preventDefault(); $("#f-tunnel").checked = !$("#f-tunnel").checked; syncTunnel(); }
    });
    $("#adv-toggle").addEventListener("click", () =>
      setAdv($("#adv-section").dataset.collapsed === "true")
    );
    $("#svc-save").addEventListener("click", saveService);
    $("#pw-save").addEventListener("click", changePassword);

    // 首次引导
    $("#wiz-save").addEventListener("click", saveWizard);
    $("#wiz-rows").addEventListener("click", (e) => {
      const del = e.target.closest("[data-wiz-del]");
      if (!del) return;
      readWizardRows();
      WIZ.rows.splice(+del.dataset.wizDel, 1);
      renderWizard();
    });
    $("#wiz-rows").addEventListener("change", (e) => {
      // 只有切换 port/domain 需要重画（要显示/隐藏主机那一栏）
      if (e.target.dataset.f === "mode") { readWizardRows(); renderWizard(); }
    });
    $("#wizard").addEventListener("click", (e) => {
      const add = e.target.closest("[data-wiz-add]");
      if (add) addWizardRow(add.dataset.wizAdd);
    });

    // 端口发现
    $("#d-preset").addEventListener("change", syncPreset);
    $("#d-run").addEventListener("click", runDiscover);
    $("#d-add").addEventListener("click", addDiscovered);
    $("#d-stop").addEventListener("click", () => DISC.ctrl && DISC.ctrl.abort());
    $("#d-host").addEventListener("keydown", (e) => { if (e.key === "Enter") runDiscover(); });
    $("#d-ports").addEventListener("keydown", (e) => { if (e.key === "Enter") runDiscover(); });
    $("#d-list").addEventListener("click", (e) => {
      e.preventDefault();   // 整行是 <label>，默认行为会再触发一次
      const edit = e.target.closest("[data-edit]");
      if (edit) {
        const r = DISC.rows.find((x) => x.port === +edit.dataset.edit);
        // 两个弹窗同级，叠着看不清，先收起发现窗（结果还在，再打开就还能看到）
        closeOverlay("#disc-overlay");
        if (r) openServiceModal(discToService(r));
        return;
      }
      const row = e.target.closest("[data-port]");
      if (row) toggleDiscRow(+row.dataset.port, row);
    });

    // 关闭 modal：X / 取消 / 点遮罩 / Esc
    $$("[data-close]").forEach((el) =>
      el.addEventListener("click", () => el.closest(".overlay").classList.remove("open"))
    );
    $$(".overlay").forEach((ov) =>
      ov.addEventListener("click", (e) => { if (e.target === ov) ov.classList.remove("open"); })
    );
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        if ($("#disc-overlay").classList.contains("open") && DISC.ctrl) DISC.ctrl.abort();
        $$(".overlay.open").forEach((o) => o.classList.remove("open"));
      }
      // 在服务表单里按 Ctrl/⌘+Enter 保存
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && $("#svc-overlay").classList.contains("open")) saveService();
    });
  }

  // ============================================================
  //  端口发现
  // ============================================================
  // 服务端用 SSE 边扫边推（见 app.py /api/discover），这里手动解析事件流：
  // EventSource 只能发 GET，而我们要 POST 参数，所以用 fetch + ReadableStream。
  const DISC = { running: false, ctrl: null, rows: [], sel: new Set(), total: 0 };

  const CONF_LABEL = { high: "已识别", medium: "可能", low: "疑似", none: "未知" };

  function openDiscover() {
    const hosts = STATE.networks.filter((n) => n.host).map((n) => n.host);
    $("#d-host-list").innerHTML = hosts.map((h) => `<option value="${escapeHtml(h)}">`).join("");
    if (!$("#d-host").value) {
      const cur = netById(STATE.detected);
      $("#d-host").value = (cur && cur.host) || hosts[0] || location.hostname;
    }
    hideErr("#d-err");
    renderDiscRows();
    openOverlay("#disc-overlay");
  }

  function syncPreset() {
    $("#d-custom-field").dataset.collapsed =
      $("#d-preset").value === "custom" ? "false" : "true";
  }

  async function runDiscover() {
    if (DISC.running) return;
    const host = $("#d-host").value.trim();
    if (!host) return showErr("#d-err", "请填写要扫描的主机");
    const preset = $("#d-preset").value;
    const ports = preset === "custom" ? $("#d-ports").value.trim() : preset;
    if (preset === "custom" && !ports) return showErr("#d-err", "请填写要扫描的端口");

    DISC.running = true;
    DISC.rows = [];
    DISC.sel.clear();
    DISC.total = 0;
    $("#d-list").innerHTML = "";
    $("#d-empty").hidden = true;
    $("#d-progress").hidden = false;
    $("#d-fill").style.width = "0%";
    $("#d-stat").innerHTML = "<span>正在连接…</span>";
    $("#d-run").disabled = true;
    $("#d-run").textContent = "扫描中…";
    $("#d-stop").hidden = false;
    hideErr("#d-err");
    updateDiscCount();

    const ctrl = new AbortController();
    DISC.ctrl = ctrl;
    try {
      const res = await fetch("/api/discover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: host, ports: ports }),
        signal: ctrl.signal,
      });
      if (res.status === 401) { location.href = "/login"; return; }
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || "HTTP " + res.status);
      }
      await readEventStream(res.body, onDiscEvent);
    } catch (e) {
      if (e.name !== "AbortError") showErr("#d-err", e.message || "扫描失败");
    } finally {
      finishDiscover();
    }
  }

  // 手写一个够用的 SSE 解析：按空行切事件，只认 data: 行
  async function readEventStream(stream, onEvent) {
    const reader = stream.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const r = await reader.read();
      if (r.done) break;
      buf += dec.decode(r.value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        for (const line of block.split("\n")) {
          if (line.slice(0, 5) !== "data:") continue;
          let ev = null;
          try { ev = JSON.parse(line.slice(5)); } catch (_) { continue; }
          onEvent(ev);
        }
      }
    }
  }

  function onDiscEvent(ev) {
    if (ev.type === "start") {
      DISC.total = ev.total;
      $("#d-stat").innerHTML =
        `<span>${escapeHtml(ev.host)} (${escapeHtml(ev.ip)}) · ${ev.total} 个端口</span><span>0%</span>`;
    } else if (ev.type === "progress") {
      const pct = ev.total ? Math.round((ev.done / ev.total) * 100) : 0;
      $("#d-fill").style.width = pct + "%";
      $("#d-stat").innerHTML =
        `<span>${ev.done} / ${ev.total}</span>` +
        `<span class="hit">开放 ${ev.open} · ${pct}%</span>`;
    } else if (ev.type === "scanned") {
      $("#d-fill").style.width = "100%";
      $("#d-stat").innerHTML = ev.open.length
        ? `<span>扫描完成 ${ev.elapsed}s，正在识别 ${ev.open.length} 个开放端口…</span>`
        : `<span>扫描完成 ${ev.elapsed}s</span>`;
    } else if (ev.type === "found") {
      DISC.rows.push(ev);
      DISC.rows.sort((a, b) => a.port - b.port);
      renderDiscRows();
    } else if (ev.type === "done") {
      $("#d-stat").innerHTML =
        `<span>共 ${ev.total} 个端口，开放 ${ev.open} 个</span><span>用时 ${ev.elapsed}s</span>`;
    } else if (ev.type === "unreliable") {
      // 目标来者不拒，扫了也是白扫 —— 直接说清楚，并指一条活路
      $("#d-progress").hidden = true;
      const alt = STATE.networks
        .filter((n) => n.host && n.host !== ev.host)
        .map((n) => `${n.name} ${n.host}`);
      showErr("#d-err", ev.message +
        (alt.length ? "　建议换成这台机器的真实网卡地址再试：" + alt.join("、") : ""));
    } else if (ev.type === "error") {
      showErr("#d-err", ev.message);
    }
  }

  function finishDiscover() {
    DISC.running = false;
    DISC.ctrl = null;
    $("#d-run").disabled = false;
    $("#d-run").textContent = "重新扫描";
    $("#d-stop").hidden = true;
    $("#d-empty").hidden = DISC.rows.length > 0;
  }

  // 已经在索引里的端口不再重复添加
  function indexedPorts() {
    const m = new Map();
    for (const s of STATE.services) if (s.port) m.set(s.port, s.name);
    return m;
  }

  function renderDiscRows() {
    const have = indexedPorts();
    $("#d-list").innerHTML = DISC.rows
      .map((r) => {
        const owned = have.get(r.port);
        const on = !owned && DISC.sel.has(r.port);
        const tag = owned
          ? `<span class="disc-tag have">已在索引</span>`
          : `<span class="disc-tag ${escapeHtml(r.confidence)}">${CONF_LABEL[r.confidence] || "未知"}</span>`;
        // 非 HTTP 的端口（SSH / 数据库 …）加进索引后卡片是点不开的，先说清楚
        const nonWeb = r.web ? "" : `<span class="disc-nonweb">非 Web</span>`;
        const sub = owned
          ? `已添加为「${escapeHtml(owned)}」`
          : nonWeb + escapeHtml(r.evidence || "端口开放，但没探到更多信息");
        const edit = owned
          ? ""
          : `<button class="icon-btn" data-edit="${r.port}" title="编辑后添加">✎</button>`;
        return `<label class="disc-row${owned ? " have" : ""}${on ? " on" : ""}" data-port="${r.port}">
                  <div class="avatar" style="${avatarStyle(r.name)}">${escapeHtml(r.icon || "🔌")}</div>
                  <div class="body">
                    <div class="l1">
                      <span class="nm">${escapeHtml(r.name)}</span>
                      <span class="pt">:${r.port}</span>
                    </div>
                    <div class="l2" title="${escapeHtml(r.evidence || "")}">${sub}</div>
                  </div>
                  ${edit}${tag}
                </label>`;
      })
      .join("");
    updateDiscCount();
  }

  function updateDiscCount() {
    const n = DISC.sel.size;
    $("#d-count").textContent = DISC.rows.length
      ? `发现 ${DISC.rows.length} 个开放端口${n ? "，已选 " + n : ""}`
      : "";
    $("#d-add").disabled = n === 0;
    $("#d-add").textContent = n ? `添加选中 (${n})` : "添加选中";
  }

  // 只翻这一行的样式，不整表重画 —— 否则列表滚动位置会被顶回去，
  // 每行的入场动画也会重放一遍
  function toggleDiscRow(port, row) {
    if (!row || row.classList.contains("have")) return;
    if (DISC.sel.has(port)) DISC.sel.delete(port);
    else DISC.sel.add(port);
    row.classList.toggle("on", DISC.sel.has(port));
    updateDiscCount();
  }

  // 把一条发现结果翻译成服务表单的字段
  function discToService(r) {
    return {
      name: r.name,
      icon: r.icon,
      desc: r.title && r.title !== r.name ? r.title.slice(0, 60) : "",
      category: r.category,
      port: r.port,
      // http 留空走网络默认；https 必须写死，否则点进去会走错协议
      scheme: r.scheme === "https" ? "https" : "",
      tunnel: false,
      domain: "",
      path: "",
    };
  }

  async function addDiscovered() {
    const picked = DISC.rows.filter((r) => DISC.sel.has(r.port));
    if (!picked.length) return;
    const btn = $("#d-add");
    btn.disabled = true;
    hideErr("#d-err");
    let latest = null;
    const failed = [];
    for (const r of picked) {
      try {
        latest = await api("POST", "/api/services", discToService(r));
      } catch (e) {
        failed.push(`${r.name}:${r.port} — ${e.message}`);
      }
    }
    if (latest) applyConfig(latest);
    DISC.sel.clear();
    renderDiscRows();
    if (failed.length) showErr("#d-err", "部分未添加：" + failed.join("；"));
    const ok = picked.length - failed.length;
    if (ok) toast(`已添加 ${ok} 个服务`, "ok");
  }

  // ============================================================
  //  服务健康状态（运行 / 离线）
  // ============================================================
  const HEALTH_INTERVAL = 20000;
  let healthTimer = null;

  /** 就地更新状态点，不重建卡片 —— 轮询回来时不该让整个网格闪一下。 */
  function updateHealthDots() {
    $$(".card").forEach((card) => {
      const dot = card.querySelector('[data-role="status"]');
      if (!dot) return;
      const st = STATE.health[card.dataset.id] || "unknown";
      dot.className = "status-dot " + st;
      dot.title = healthTitle(card.dataset.id);
    });
  }

  async function refreshHealth() {
    if (!STATE.view) return;
    try {
      const data = await api("GET", "/api/health?network=" + encodeURIComponent(STATE.view));
      STATE.health = data.states || {};
      STATE.healthVia = data.via || {};
      updateHealthDots();
    } catch (e) {
      // 静默失败，下一轮再试。探测挂了不该弹提示打扰人。
    }
  }

  function startHealthPolling() {
    if (healthTimer) return;
    // 页面在后台就跳过：这是服务端发起的一批 TCP 连接，没人看的时候纯属白烧。
    healthTimer = setInterval(() => {
      if (!document.hidden) refreshHealth();
    }, HEALTH_INTERVAL);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) refreshHealth();
    });
  }

  // ---------- 启动 ----------
  async function init() {
    bind();
    try {
      const data = await api("GET", "/api/config");
      applyConfig(data);
    } catch (e) {
      if (e.message !== "unauthorized") toast("加载失败：" + e.message, "err");
    }
  }

  init();
})();
