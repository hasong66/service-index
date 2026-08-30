// 登录 / 首次设置密码
(function () {
  const mode = document.body.dataset.mode; // 'login' | 'setup'
  const $ = (s) => document.querySelector(s);
  const isSetup = mode === "setup";

  $("#auth-title").textContent = isSetup ? "首次使用 · 设置密码" : "服务索引";
  $("#auth-sub").textContent = isSetup
    ? "设置一个访问密码，将以哈希形式加密保存"
    : "请输入访问密码";
  $("#auth-btn").textContent = isSetup ? "设置并进入" : "进入";
  if (isSetup) {
    $("#confirm-field").hidden = false;
    $("#pw").setAttribute("autocomplete", "new-password");
    $("#pw").placeholder = "设置密码（至少 6 位）";
  }

  const errEl = $("#auth-err");
  const btn = $("#auth-btn");
  const showErr = (m) => { errEl.textContent = m || ""; };

  async function submit() {
    const pw = $("#pw").value;
    if (!pw) return showErr("请输入密码");
    if (isSetup) {
      if (pw.length < 6) return showErr("密码至少 6 位");
      if (pw !== $("#pw2").value) return showErr("两次输入不一致");
    }
    btn.disabled = true;
    showErr("");
    try {
      // 密码在这里就加密好，请求体里只有密文（见 static/crypto.js）
      const field = isSetup ? "setup" : "login";
      const enc = await PwCrypto.encrypt({ [field]: pw });
      const res = await fetch(isSetup ? "/api/setup" : "/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enc: enc[field] }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        location.href = "/";
        return;
      }
      showErr(data.error || "操作失败");
    } catch (e) {
      showErr(e && e.message ? e.message : "网络错误，请重试");
    } finally {
      btn.disabled = false;
    }
  }

  btn.addEventListener("click", submit);
  [$("#pw"), $("#pw2")].forEach((el) =>
    el && el.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); })
  );
  $("#pw").focus();
})();
