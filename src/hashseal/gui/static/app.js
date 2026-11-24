/* hashseal GUI：路由与页面 */

import { api, ApiFail, initToken, hasToken, runTask } from "./api.js";
import {
  el, icon, fmtBytes, fmtTime, shortPath, toast, copyText,
  openModal, confirmModal, pickPath, commandForm, taskResult, argvToCommand,
} from "./ui.js";

const state = {
  status: null,
  commands: new Map(),
  sectionCommands: {},
  sections: [],
  activeCommand: {},
  currentRoute: "",
};

const EYEBROW = {
  "": "OVERVIEW", verify: "VERIFY", sign: "SIGN", keys: "KEYS",
  dirs: "DIRECTORIES", stamps: "TIMESTAMPS", tools: "TOOLS",
  audit: "AUDIT", settings: "SETTINGS",
};

const SECTION_LABEL = {
  verify: "验证", sign: "签名", keys: "密钥", dirs: "目录与分发",
  stamps: "时间戳与证明", tools: "工具", settings: "设置",
};

/* ---------- 启动 ---------- */

async function boot() {
  initToken();
  window.addEventListener("hashchange", route);
  window.addEventListener("hashseal:unauthorized", showUnauthorized);
  if (!hasToken()) return renderNoToken();
  try {
    const [status, cmdData] = await Promise.all([api.status(), api.commands()]);
    state.status = status;
    state.sections = cmdData.sections;
    state.sectionCommands = cmdData.section_commands;
    for (const cmd of cmdData.commands) state.commands.set(cmd.name, cmd);
  } catch (err) {
    renderFatal(err);
    return;
  }
  document.getElementById("side-ver").textContent = "v" + state.status.version;
  updateVaultChip();
  route();
}

function showUnauthorized() {
  const main = document.getElementById("main");
  main.textContent = "";
  main.append(el("div", { class: "content" },
    el("div", { class: "banner fail", style: "margin-top:60px" }, icon("alert"),
      el("div", {},
        el("strong", {}, "会话无效"),
        el("div", { class: "sub" },
          "服务已重启或口令会话已失效。请回到终端复制新的地址（含 #token=…）重新打开。")))));
}

function renderNoToken() {
  const main = document.getElementById("main");
  main.textContent = "";
  main.append(el("div", { class: "content" },
    el("div", { class: "banner warn", style: "margin-top:60px" }, icon("alert"),
      el("div", {},
        el("strong", {}, "缺少访问令牌"),
        el("div", { class: "sub" },
          "请使用终端中显示的完整地址打开（形如 http://127.0.0.1:端口/#token=…）。")))));
}

function renderFatal(err) {
  const main = document.getElementById("main");
  main.textContent = "";
  main.append(el("div", { class: "content" },
    el("div", { class: "banner fail" }, icon("alert"),
      el("div", {},
        el("strong", {}, "无法连接服务"),
        el("div", { class: "sub" }, err && err.message ? err.message : String(err))))));
}

/* ---------- 路由 ---------- */

const NAV_ORDER = ["", "keys", "sign", "verify", "stamps", "dirs", "tools", "audit", "settings"];

function route() {
  const hash = location.hash.replace(/^#\/?/, "");
  const prev = NAV_ORDER.indexOf(state.currentRoute);
  const next = NAV_ORDER.indexOf(hash);
  const dir =
    prev === -1 || prev === next || next === -1
      ? "forward"
      : next > prev
        ? "forward"
        : "back";
  state.currentRoute = hash;
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.classList.toggle("active", (a.dataset.route || "") === hash);
  });
  const main = document.getElementById("main");
  main.scrollTop = 0;

  // 旧页离场（3D 翻页离场），新页入场
  const old = main.querySelector(":scope > .page");
  if (old) {
    old.classList.remove("stagger");
    old.classList.add("page-leave-" + dir);
    setTimeout(() => old.remove(), 460);
  }
  const page = el("div", { class: "page page-enter-" + dir + " stagger" });
  main.append(page);

  if (hash === "") return pageDashboard(page);
  if (hash === "audit") return pageAudit(page);
  if (hash === "settings") return pageSettings(page);
  if (state.sectionCommands[hash]) return pageCommands(page, hash);
  page.append(el("div", { class: "banner warn" }, icon("alert"), el("div", {}, "页面不存在")));
}

function pageHead(sectionId, title, desc) {
  return el("div", { class: "page-head" },
    el("div", { class: "eyebrow" }, EYEBROW[sectionId] || "HASHSEAL"),
    el("h1", { class: "page-title" }, title),
    desc ? el("p", { class: "page-desc" }, desc) : null);
}

/* ---------- 概览 ---------- */

async function pageDashboard(page) {
  const content = el("div", { class: "content stagger" });

  const hero = el("div", { class: "hero" },
    el("div", { class: "hero-inner" },
      el("div", { class: "hero-kicker" }, "HASHSEAL · SHA-256 + ED25519 + RFC 3161"),
      el("div", { class: "hero-title" }, "证明文件没被改过、"),
      el("div", { class: "hero-title", style: "color:var(--muted)" }, "是谁发的、什么时候发的。"),
      el("p", { class: "hero-sub" },
        "在浏览器完成签名、验证、时间戳与分发校验；与 CLI 共用同一套密钥、配置与审计日志。"),
      el("div", { class: "hero-actions" },
        el("button", { class: "btn btn-primary", onclick: () => { location.hash = "#/keys"; } }, "生成密钥"),
        el("button", { class: "btn btn-ghost", onclick: () => { location.hash = "#/sign"; } }, "签名文件"),
        el("button", { class: "btn btn-ghost", onclick: () => { location.hash = "#/verify"; } }, "开始验证")),
      el("div", { class: "hero-art", "aria-hidden": "true", html:
        '<svg viewBox="0 0 300 170" fill="none" stroke="currentColor" stroke-width="1">' +
        '<circle cx="215" cy="55" r="42"/><path d="M198 55l12 12 22-24"/>' +
        '<rect x="30" y="70" width="86" height="86" rx="4"/>' +
        '<path d="M46 92h54M46 108h54M46 124h32"/>' +
        '<circle cx="73" cy="55" r="20"/><path d="M108 30l14-14M120 42l20-8"/>' +
        "</svg>" })),
  );

  const quick = el("div", { class: "quick-grid" });
  for (const [section, iconName, text, desc] of [
    ["keys", "key", "第一步：生成密钥", "生成 Ed25519 密钥对，核对公钥指纹"],
    ["sign", "pen", "第二步：签名文件", "生成 .sig，可选 RFC 3161 时间戳"],
    ["verify", "shield", "第三步：验证签名", "核对内容、签名者与时间戳"],
  ]) {
    quick.append(el("button", {
      class: "card quick-card", type: "button",
      onclick: () => { location.hash = "#/" + section; },
    },
      el("div", { class: "card-title" }, icon(iconName), text),
      el("p", { class: "card-desc", style: "margin:6px 0 0" }, desc)));
  }

  const dash = el("div", { class: "dash-cols", style: "margin-top:18px" });
  const tasksCard = el("div", { class: "card" },
    el("div", { class: "card-head" }, el("div", { class: "card-title" }, "最近操作")),
    el("div", { class: "field-help" }, "加载中…"));
  const auditCard = el("div", { class: "card" },
    el("div", { class: "card-head" }, el("div", { class: "card-title" }, "审计日志（最近 6 条）")),
    el("div", { class: "field-help" }, "加载中…"));

  if (state.status.read_only) {
    content.append(el("div", { class: "note-bar" }, icon("alert"),
      el("span", {}, "当前为只读模式：签名、生成、解包等写操作已在服务端禁用。")));
  }
  content.append(hero, quick, dash);
  dash.append(tasksCard, auditCard);
  page.append(content);

  try {
    const { tasks } = await api.tasks();
    tasksCard.textContent = "";
    tasksCard.append(el("div", { class: "card-head" }, el("div", { class: "card-title" }, "最近操作")));
    if (!tasks.length) {
      tasksCard.append(el("p", { class: "field-help" }, "暂无操作记录"));
    } else {
      tasksCard.append(el("div", { class: "table-wrap" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, "时间"), el("th", {}, "命令"), el("th", {}, "状态"))),
        el("tbody", {}, tasks.slice(0, 8).map((t) => el("tr", {},
          el("td", {}, (t.finished || t.started || t.created || "").replace("T", " ").slice(0, 19)),
          el("td", {}, t.command),
          el("td", {}, el("span", { class: "badge " + (t.state === "succeeded" ? "ok" : t.state === "failed" ? "fail" : "info") }, t.state))))))));
    }
  } catch { /* 忽略 */ }

  try {
    const { events } = await api.audit(6);
    auditCard.textContent = "";
    auditCard.append(el("div", { class: "card-head" }, el("div", { class: "card-title" }, "审计日志（最近 6 条）")));
    if (!events.length) {
      auditCard.append(el("p", { class: "field-help" }, "暂无审计记录"));
    } else {
      auditCard.append(el("div", { class: "table-wrap" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, "时间"), el("th", {}, "事件"), el("th", {}, "对象"))),
        el("tbody", {}, events.slice(0, 6).map((r) => el("tr", {},
          el("td", {}, String(r.ts_local || r.ts || "").slice(0, 19)),
          el("td", {}, String(r.event || "")),
          el("td", { class: "mono" }, shortPath(String(r.path || r.public || ""), 28))))))));
    }
  } catch { /* 忽略 */ }

  content.append(el("div", { class: "card", style: "margin-top:18px" },
    el("div", { class: "card-title", style: "margin-bottom:10px" }, "安全提示"),
    el("ul", { class: "warn-list", style: "color:var(--muted)" },
      el("li", {}, "GUI 只能访问启动时指定的根目录（", state.status.roots.join("、"), "）内的文件。"),
      el("li", {}, "地址中的 #token=… 是本服务的唯一凭证，请勿分享或截图。"),
      el("li", {}, "私钥口令只保存在本进程内存中，点击侧栏“锁定”或退出程序即清除。"))));
}

/* ---------- 命令页 ---------- */

function pageCommands(page, sectionId) {
  const commands = state.sectionCommands[sectionId] || [];
  if (!state.activeCommand[sectionId]) state.activeCommand[sectionId] = commands[0];

  const content = el("div", { class: "content stagger" });
  content.append(pageHead(
    sectionId,
    SECTION_LABEL[sectionId] || sectionId,
    state.commands.get(commands[0]) ? "" : "",
  ));

  if (state.status.read_only && commands.every((c) => state.commands.get(c).mutating)) {
    content.append(el("div", { class: "note-bar" }, icon("alert"),
      el("span", {}, "只读模式：本页操作已在服务端禁用。")));
  }

  const tabs = el("div", { class: "cmd-tabs" });
  const cardBox = el("div", {});

  const renderCard = () => {
    const name = state.activeCommand[sectionId];
    const cmd = state.commands.get(name);
    cardBox.textContent = "";
    cardBox.append(commandCard(cmd));
  };

  for (const name of commands) {
    const cmd = state.commands.get(name);
    const tab = el("button", {
      class: "cmd-tab" + (name === state.activeCommand[sectionId] ? " active" : ""),
      type: "button",
      onclick: () => {
        state.activeCommand[sectionId] = name;
        tabs.querySelectorAll(".cmd-tab").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        renderCard();
      },
    }, cmd.title, cmd.mutating ? el("span", { class: "mut-dot", title: "写操作" }) : null);
    tabs.append(tab);
  }

  content.append(tabs, cardBox);
  page.append(content);
  renderCard();

  if (sectionId === "keys") {
    content.insertBefore(vaultCard(), tabs);
  }
}

function commandCard(cmd) {
  const card = el("div", { class: "card flowing" });
  card.append(
    el("div", { class: "card-head" },
      el("div", { class: "card-title" }, cmd.title),
      cmd.mutating ? el("span", { class: "badge info" }, "写操作") : el("span", { class: "badge info" }, "只读")),
    el("p", { class: "card-desc" }, cmd.desc),
  );
  const resultBox = el("div", {});
  const form = commandForm(cmd, {
    submitLabel: cmd.title,
    onSubmit: (options) => execute(cmd, options, resultBox),
  });
  card.append(form, resultBox);
  return card;
}

async function execute(cmd, options, resultBox) {
  resultBox.textContent = "";
  const running = el("div", { class: "running" },
    el("div", { class: "spinner" }),
    el("span", {}, "已提交，等待执行…"));
  let cancelBtn = null;
  if (cmd.cancelable) {
    cancelBtn = el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => api.cancel(currentTaskId || "") }, "取消");
    running.append(cancelBtn);
  }
  resultBox.append(running);
  let currentTaskId = null;
  const onTask = (task) => {
    currentTaskId = task.id;
    if (task.progress && task.state === "running") {
      const { stage, done, total } = task.progress;
      running.querySelector("span").textContent =
        total ? `${stage} ${done}/${total}` : (stage || "执行中…");
      if (total) {
        let bar = running.querySelector("progress");
        if (!bar) { bar = el("progress", { class: "runbar", max: total }); running.append(bar); }
        bar.value = done;
        bar.max = total;
      }
    }
  };
  try {
    const task = await runTask(cmd.name, options, onTask);
    resultBox.textContent = "";
    resultBox.append(taskResult(cmd.name, task));
    if (task.state === "succeeded") updateVaultChip();
  } catch (err) {
    resultBox.textContent = "";
    if (err instanceof ApiFail) {
      resultBox.append(el("div", { class: "banner fail" }, icon("alert"),
        el("div", {}, el("strong", {}, "提交失败"),
          el("div", { class: "sub" }, err.message + (err.hint ? "（" + err.hint + "）" : "")))));
    } else {
      resultBox.append(el("div", { class: "banner fail" }, icon("alert"),
        el("div", {}, el("strong", {}, "发生错误"), el("div", { class: "sub" }, String(err)))));
    }
  }
}

/* ---------- 口令保管 ---------- */

function updateVaultChip() {
  const chip = document.getElementById("vault-chip");
  if (!state.status) return;
  api.vault().then(({ keys }) => {
    state.status.vault = { keys };
    chip.textContent = "";
    chip.append(icon(keys.length ? "unlock" : "lock"),
      el("span", {}, keys.length ? `已记住 ${keys.length} 个口令` : "未记住口令"));
  }).catch(() => {});
}

function vaultCard() {
  const card = el("div", { class: "card" },
    el("div", { class: "card-head" },
      el("div", { class: "card-title" }, "口令保管"),
      el("button", {
        class: "btn btn-ghost btn-sm", type: "button",
        onclick: async () => {
          const ok = await confirmModal({
            title: "锁定全部口令",
            message: "将清除本进程记住的所有私钥口令。之后的加密私钥操作需要重新输入。",
            confirmLabel: "锁定",
            danger: true,
          });
          if (!ok) return;
          await api.lock();
          toast("已锁定", "ok");
          refreshVault();
        },
      }, icon("lock"), "全部锁定")),
    el("p", { class: "card-desc" }, "口令只保存在本进程内存中，绝不写盘；退出程序即清空。"));

  const keyInput = el("input", { type: "text", placeholder: "私钥路径", "aria-label": "私钥路径" });
  const pwInput = el("input", { type: "password", placeholder: "私钥口令", "aria-label": "私钥口令", autocomplete: "current-password" });
  const list = el("div", { class: "chips", style: "margin-top:10px" });

  const refreshVault = async () => {
    try {
      const { keys } = await api.vault();
      list.textContent = "";
      if (!keys.length) list.append(el("span", { class: "field-help" }, "尚未记住任何口令"));
      for (const key of keys) {
        list.append(el("span", { class: "chip" }, shortPath(key, 40),
          el("button", { class: "chip-x", type: "button", title: "清除", onclick: async () => { await api.lock(key); refreshVault(); updateVaultChip(); } }, icon("x"))));
      }
    } catch { /* ignore */ }
  };

  const unlockBtn = el("button", {
    class: "btn btn-primary btn-sm", type: "button",
    onclick: async () => {
      const key = keyInput.value.trim();
      if (!key || !pwInput.value) { toast("请填写私钥路径与口令", "fail"); return; }
      try {
        const res = await api.unlock(key, pwInput.value);
        pwInput.value = "";
        toast("已解锁：" + res.fingerprint, "ok");
        refreshVault();
        updateVaultChip();
      } catch (err) {
        toast(err instanceof ApiFail ? err.message : "解锁失败", "fail");
      }
    },
  }, "解锁并记住");

  card.append(
    el("div", { class: "form-grid" },
      el("div", { class: "field" },
        el("label", { class: "field-label" }, el("span", {}, "私钥")),
        el("div", { class: "field-row" }, keyInput,
          el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: async () => {
            const picked = await pickPath({ mode: "any", title: "选择私钥文件" });
            if (picked) keyInput.value = Array.isArray(picked) ? picked[0] : picked;
          } }, icon("folder"), "浏览…"))),
      el("div", { class: "field" },
        el("label", { class: "field-label" }, el("span", {}, "口令")),
        pwInput),
      el("div", { class: "form-actions", style: "margin-top:4px" }, unlockBtn)),
    el("div", { style: "margin-top:14px" },
      el("div", { class: "field-label" }, el("span", {}, "已记住的密钥")),
      list));
  refreshVault();
  return card;
}

/* ---------- 审计 ---------- */

async function pageAudit(page) {
  const content = el("div", { class: "content stagger" });
  content.append(pageHead("audit", "审计日志", "所有 CLI 与 GUI 操作都会记录；GUI 记录的 source 为 gui。"));

  const linesSelect = el("select", {},
    ...[50, 100, 300, 500].map((n) => el("option", { value: n }, `${n} 条`)));
  linesSelect.value = "100";
  const filterInput = el("input", { type: "text", placeholder: "按事件/路径过滤…" });
  const tableBox = el("div", {});
  let rawMode = false;
  let events = [];

  const render = () => {
    tableBox.textContent = "";
    const kw = filterInput.value.trim().toLowerCase();
    const shown = events.filter((r) => {
      if (!kw) return true;
      return JSON.stringify(r).toLowerCase().includes(kw);
    });
    if (rawMode) {
      tableBox.append(el("div", { class: "table-wrap" },
        el("pre", { style: "margin:0;padding:12px;background:var(--bg-deep);color:var(--muted);font-family:var(--mono);font-size:12px;max-height:520px;overflow:auto" },
          shown.map((r) => JSON.stringify(r)).join("\n"))));
      return;
    }
    tableBox.append(el("div", { class: "table-wrap" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", {}, "时间"), el("th", {}, "事件"), el("th", {}, "来源"), el("th", {}, "结果"), el("th", {}, "详情"))),
      el("tbody", {}, shown.map((r) => {
        const extra = Object.assign({}, r);
        delete extra.ts; delete extra.ts_local; delete extra.event; delete extra.source; delete extra.user; delete extra.hostname; delete extra.uid;
        return el("tr", {},
          el("td", {}, String(r.ts_local || r.ts || "").slice(0, 19)),
          el("td", {}, String(r.event || "")),
          el("td", {}, String(r.source || "cli")),
          el("td", {}, r.ok === undefined ? "—" : r.ok ? "✅" : "❌"),
          el("td", { class: "mono" }, shortPath(JSON.stringify(extra), 90)));
      })))));
  };

  const load = async () => {
    try {
      const data = await api.audit(Number(linesSelect.value));
      events = data.events || [];
      render();
    } catch (err) {
      toast(err.message || "加载失败", "fail");
    }
  };

  linesSelect.addEventListener("change", load);
  filterInput.addEventListener("input", render);

  content.append(el("div", { class: "card" },
    el("div", { class: "form-actions", style: "margin-bottom:14px" },
      linesSelect,
      filterInput,
      el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: load }, icon("refresh"), "刷新"),
      el("button", {
        class: "btn btn-ghost btn-sm", type: "button",
        onclick: () => { rawMode = !rawMode; render(); },
      }, "原始 JSON")),
    tableBox));
  page.append(content);
  load();
}

/* ---------- 设置 ---------- */

function pageSettings(page) {
  const content = el("div", { class: "content stagger" });
  content.append(pageHead("settings", "设置", "配置、根目录与服务信息。"));

  const cfg = state.status.config || {};
  const cfgKv = el("div", { class: "kv" });
  for (const [key, value] of Object.entries(cfg)) {
    cfgKv.append(...[
      el("div", { class: "k mono" }, key),
      el("div", { class: "v mono" }, typeof value === "object" ? JSON.stringify(value) : String(value)),
    ]);
  }
  if (!Object.keys(cfg).length) cfgKv.append(el("div", { class: "k" }), el("div", { class: "v" }, "（使用默认值）"));

  content.append(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, "配置文件"),
    el("div", { class: "kv" },
      el("div", { class: "k" }, "路径"), el("div", { class: "v mono" }, state.status.config_path),
      el("div", { class: "k" }, "生效配置"), el("div", { class: "v" }, "")),
    cfgKv,
    el("div", { style: "margin-top:12px" }, el("a", { href: "https://renengade.github.io/hashseal/config", target: "_blank", rel: "noreferrer" }, "配置说明（docs）↗"))));

  content.append(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, "可访问的根目录"),
    el("p", { class: "card-desc" }, "GUI 只能读写以下目录内的文件；如需更多目录，用 --root 重启。"),
    el("div", { class: "chips" }, state.status.roots.map((r) => el("span", { class: "chip" }, r)))));

  const initCmd = state.commands.get("config-init");
  if (initCmd) {
    const resultBox = el("div", {});
    content.append(el("div", { class: "card" },
      el("div", { class: "card-head" }, el("div", { class: "card-title" }, initCmd.title)),
      el("p", { class: "card-desc" }, initCmd.desc),
      commandForm(initCmd, { onSubmit: (options) => execute(initCmd, options, resultBox) }),
      resultBox));
  }

  content.append(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, "服务信息"),
    el("div", { class: "kv" },
      el("div", { class: "k" }, "版本"), el("div", { class: "v mono" }, state.status.version),
      el("div", { class: "k" }, "Python"), el("div", { class: "v mono" }, state.status.python),
      el("div", { class: "k" }, "审计日志"), el("div", { class: "v mono" }, state.status.audit_path),
      el("div", { class: "k" }, "闲置退出"), el("div", { class: "v" }, state.status.idle_timeout_minutes ? `${state.status.idle_timeout_minutes} 分钟` : "不自动退出"),
      el("div", { class: "k" }, "口令闲置锁定"), el("div", { class: "v" }, state.status.vault_timeout_minutes ? `${state.status.vault_timeout_minutes} 分钟` : "直到退出")),
    el("div", { class: "form-actions" },
      el("button", {
        class: "btn btn-danger", type: "button",
        onclick: async () => {
          const ok = await confirmModal({
            title: "退出 hashseal GUI",
            message: "将停止本地服务并清除记住的口令。CLI 不受影响。",
            confirmLabel: "退出服务",
            danger: true,
          });
          if (!ok) return;
          try { await api.shutdown(); } catch { /* ignore */ }
          document.getElementById("main").textContent = "";
          document.getElementById("main").append(el("div", { class: "content" },
            el("div", { class: "banner ok" }, icon("check"),
              el("div", {}, el("strong", {}, "服务已退出"), el("div", { class: "sub" }, "可关闭此页面。")))));
        },
      }, "退出服务"))));
  page.append(content);
}

boot();
