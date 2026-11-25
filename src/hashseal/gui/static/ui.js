/* UI 组件：DOM 助手、弹窗、toast、路径选择器、表单渲染、结果渲染 */

import { api, ApiFail } from "./api.js";

/* ---------- 基础 ---------- */

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "html") node.innerHTML = value; /* 仅用于内置静态标记 */
    else if (key.startsWith("on") && typeof value === "function")
      node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, value);
  }
  appendKids(node, children);
  return node;
}

function appendKids(node, kids) {
  for (const kid of kids.flat(9)) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
}

export function icon(name, cls = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  if (cls) svg.setAttribute("class", cls);
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
}

export function fmtBytes(n) {
  if (n === null || n === undefined || n === "") return "—";
  if (n < 1024) return `${n} 字节`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function fmtTime(iso) {
  if (!iso) return "未记录";
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const pad = (x) => String(x).padStart(2, "0");
  const local = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const utc = d.toISOString().replace("T", " ").slice(0, 19);
  return `${local}（UTC ${utc}）`;
}

export function shortPath(p, max = 52) {
  if (!p) return "";
  if (p.length <= max) return p;
  return p.slice(0, 22) + " … " + p.slice(-24);
}

export async function copyText(text, label = "已复制") {
  try {
    await navigator.clipboard.writeText(text);
    toast(label, "ok");
  } catch {
    const ta = el("textarea", { style: "position:fixed;left:-9999px" });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    toast(label, "ok");
  }
}

export function toast(message, type = "info") {
  const box = document.getElementById("toasts");
  const node = el("div", { class: "toast " + type }, message);
  box.append(node);
  setTimeout(() => node.remove(), 2600);
}

/* ---------- 弹窗 ---------- */

export function openModal({ title, content, onClose }) {
  const root = document.getElementById("modal-root");
  const prev = document.activeElement;
  const close = () => {
    overlay.remove();
    document.removeEventListener("keydown", onKey);
    if (onClose) onClose();
    if (prev && prev.focus) prev.focus();
  };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const overlay = el(
    "div",
    { class: "overlay", onclick: (e) => { if (e.target === overlay) close(); } },
    el(
      "div",
      { class: "modal", role: "dialog", "aria-modal": "true" },
      el("div", { class: "modal-head" },
        el("div", { class: "modal-title" }, title),
        el("button", { class: "modal-x", type: "button", "aria-label": "关闭", onclick: close }, icon("x")),
      ),
      content,
    ),
  );
  document.addEventListener("keydown", onKey);
  root.append(overlay);
  const first = overlay.querySelector("input, select, button");
  if (first) first.focus();
  return close;
}

export function confirmModal({ title, message, confirmLabel = "继续", danger = false }) {
  return new Promise((resolve) => {
    let done = false;
    const close = (value) => {
      if (done) return;
      done = true;
      overlay.remove();
      resolve(value);
    };
    const overlay = el(
      "div",
      { class: "overlay" },
      el(
        "div",
        { class: "modal", role: "alertdialog", "aria-modal": "true" },
        el("div", { class: "modal-title", style: "margin-bottom:10px" }, title),
        el("p", { style: "color:var(--muted);font-size:13.5px;margin-bottom:18px" }, message),
        el("div", { style: "display:flex;gap:10px;justify-content:flex-end" },
          el("button", { class: "btn btn-ghost", type: "button", onclick: () => close(false) }, "取消"),
          el("button", { class: "btn " + (danger ? "btn-danger" : "btn-primary"), type: "button", onclick: () => close(true) }, confirmLabel),
        ),
      ),
    );
    document.getElementById("modal-root").append(overlay);
    overlay.querySelector(".btn-danger, .btn-primary").focus();
  });
}

/* ---------- 输入框内嵌复制按钮 ---------- */

export function withCopyInside(input, { secret = false, copy = true } = {}) {
  const wrap = el("div", { class: "input-wrap" }, input);
  const actions = el("div", { class: "input-actions" });
  if (secret) {
    const eye = el("button", {
      class: "copy-inside", type: "button", title: "显示/隐藏口令", "aria-label": "显示或隐藏口令",
      onclick: () => {
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        eye.querySelector("use").setAttribute("href", show ? "#i-eye-off" : "#i-eye");
      },
    }, icon("eye"));
    actions.append(eye);
  }
  if (copy) {
    actions.append(el("button", {
      class: "copy-inside", type: "button", title: "复制内容", "aria-label": "复制内容",
      onclick: () => {
        const value = (input.value || "").trim();
        if (!value) { toast("输入为空，没有可复制的内容", "fail"); return; }
        copyText(value);
      },
    }, icon("copy")));
  }
  wrap.append(actions);
  if (secret && copy) wrap.classList.add("dual");
  return wrap;
}

/* ---------- 路径选择器 ---------- */

const LAST_DIR_KEY = "hashseal.lastDir";

/* ---------- 路径工具（同时支持 Windows C:\ / UNC 与 POSIX） ---------- */

export function pathSep(p) {
  return String(p).includes("\\") ? "\\" : "/";
}

export function joinPath(dir, name) {
  if (!dir) return name;
  if (/[\\/]$/.test(dir)) return dir + name;
  return dir + pathSep(dir) + name;
}

export function basename(p) {
  const text = String(p).replace(/[\\/]+$/, "");
  const parts = text.split(/[\\/]/);
  return parts[parts.length - 1] || String(p);
}

export function dirname(p) {
  const text = String(p).replace(/[\\/]+$/, "");
  if (/^[A-Za-z]:$/.test(text)) return text + "\\";
  if (text.startsWith("\\\\")) {
    const match = text.match(/^\\\\[^\\]+\\[^\\]+/);
    if (match && text.length === match[0].length) return match[0] + "\\";
  }
  const idx = Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\"));
  if (idx < 0) return "";
  if (idx === 0) return text[0];
  const head = text.slice(0, idx);
  if (/^[A-Za-z]:$/.test(head)) return head + "\\";
  return head;
}

/** 拆成 {prefix, restParts}：C: / \\server\share / 空（POSIX）。 */
export function splitPathParts(p) {
  const text = String(p);
  const unc = text.match(/^\\\\[^\\]+\\[^\\]+/);
  if (unc) {
    return { prefix: unc[0], restParts: text.slice(unc[0].length).split(/[\\/]+/).filter(Boolean) };
  }
  if (/^[A-Za-z]:/.test(text)) {
    return { prefix: text.slice(0, 2), restParts: text.slice(2).split(/[\\/]+/).filter(Boolean) };
  }
  return { prefix: "", restParts: text.split(/[\\/]+/).filter(Boolean) };
}

/**
 * 打开服务端目录浏览器。
 * mode: 'any'（文件或目录）| 'dir' | 'out'（选目录 + 文件名）| 'multi'（多选文件/目录）
 */
export function pickPath({ mode = "any", title = "选择路径", initial = "", roots = [] } = {}) {
  return new Promise((resolve) => {
    let state = {
      path: null, entries: [], parent: null, filter: "", hidden: false,
      outName: "", roots: [], shortcuts: [], pickedFile: null,
    };
    const selected = new Set(); // multi 模式的多选
    let done = false;

    if (mode === "out") {
      const dir = initial ? dirname(initial) : "";
      state.path = dir || null;
      state.outName = basename(initial || "");
    } else if (mode !== "multi" && initial) {
      state.path = dirname(initial) || null;
    } else if (mode !== "multi") {
      state.path = sessionStorage.getItem(LAST_DIR_KEY) || null;
    }

    const finish = (value) => {
      if (done) return;
      done = true;
      close();
      resolve(value);
    };

    const listEl = el("div", { class: "picker-list" });
    const crumbs = el("div", { class: "crumbs" });
    const filterInput = el("input", {
      type: "text", placeholder: "按名称过滤…", "aria-label": "过滤",
      oninput: (e) => { state.filter = e.target.value.trim().toLowerCase(); renderList(); },
    });
    const hiddenInput = el("input", {
      type: "checkbox",
      onchange: (e) => { state.hidden = e.target.checked; navigate(state.path, false); },
    });
    const outNameInput = el("input", { type: "text", placeholder: "文件名", "aria-label": "文件名", value: state.outName });

    const confirmBtn = el("button", {
      class: "btn btn-primary", type: "button",
      onclick: () => {
        if (mode === "multi") {
          if (!selected.size) { toast("请先点选文件或目录", "fail"); return; }
          finish(Array.from(selected));
          return;
        }
        if (mode === "out") {
          const name = outNameInput.value.trim();
          if (!name) { toast("请填写文件名", "fail"); return; }
          finish(joinPath(state.path || roots[0] || "/", name));
          return;
        }
        finish(state.pickedFile || state.path || roots[0] || "/");
      },
    }, "确定");

    const dirSelectBtn = mode === "multi"
      ? el("button", {
          class: "btn btn-ghost", type: "button",
          onclick: () => {
            if (!state.path) return;
            if (selected.has(state.path)) selected.delete(state.path);
            else selected.add(state.path);
            updateDirBtn();
          },
        }, "选中当前目录")
      : null;

    function updateDirBtn() {
      if (!dirSelectBtn) return;
      const has = Boolean(state.path) && selected.has(state.path);
      dirSelectBtn.textContent = has ? "取消选中当前目录" : "选中当前目录";
      dirSelectBtn.disabled = !state.path;
    }

    const tick = setInterval(() => {
      confirmBtn.textContent = mode === "multi" ? `确定（已选 ${selected.size}）` : "确定";
      updateDirBtn();
      if (done) clearInterval(tick);
    }, 300);

    async function navigate(path) {
      const attempted = path || null;
      let data;
      try {
        data = await api.browse(path || "", state.hidden);
      } catch (err) {
        if (err instanceof ApiFail) {
          toast(err.message, "fail");
          if (err.code === "outside_root" && attempted) {
            state.path = null; // 记忆目录可能已不在根内 → 回到根级视图
            navigate("");
          }
        }
        return;
      }
      state.path = data.path;
      state.entries = data.entries || [];
      state.parent = data.parent;
      state.roots = data.display_roots || data.roots || roots;
      state.shortcuts = data.shortcuts || [];
      state.pickedFile = null; // 换目录后清除单选
      if (state.path) sessionStorage.setItem(LAST_DIR_KEY, state.path);
      renderCrumbs(state.roots);
      renderShortcuts();
      renderList();
      updateDirBtn();
    }

    function renderCrumbs(rootList) {
      crumbs.textContent = "";
      crumbs.append(el("button", { type: "button", onclick: () => navigate("") }, "根目录"));
      if (!state.path) return;
      const sep = pathSep(state.path);
      const { prefix, restParts } = splitPathParts(state.path);
      let acc = prefix ? prefix + sep : sep;
      if (prefix) {
        // C: 或 \\server\share 作为第一段
        const label = prefix.startsWith("\\\\") ? prefix : prefix + sep;
        crumbs.append(el("span", { class: "sep" }, sep));
        crumbs.append(el("button", { type: "button", onclick: () => navigate(acc) }, label));
      }
      restParts.forEach((part, i) => {
        acc = acc.endsWith(sep) ? acc + part : acc + sep + part;
        crumbs.append(el("button", { type: "button", onclick: () => navigate(acc) }, part));
        if (i < restParts.length - 1) crumbs.append(el("span", { class: "sep" }, sep));
      });
    }

    const shortcutBox = el("div", {});
    function shortcutChips() {
      if (!state.shortcuts.length) return null;
      const box = el("div", { class: "chips", style: "margin-bottom:8px" });
      for (const item of state.shortcuts) {
        box.append(el("button", {
          class: "chip", type: "button", style: "cursor:pointer",
          title: item.path,
          onclick: () => navigate(item.path),
        }, icon(item.label === "主目录" ? "home" : "folder"), el("span", {}, item.label)));
      }
      return box;
    }
    function renderShortcuts() {
      shortcutBox.textContent = "";
      const box = shortcutChips();
      if (box) shortcutBox.append(box);
    }

    function renderList() {
      listEl.textContent = "";
      // 根级视图：把每个根目录作为可进入的条目展示
      if (!state.path && (state.roots || roots).length) {
        for (const root of (state.roots || roots)) {
          listEl.append(el("button", {
            class: "picker-row", type: "button",
            onclick: () => navigate(root),
          }, icon("folder"), el("span", {}, root)));
        }
        return;
      }
      const entries = state.entries.filter((e2) =>
        !state.filter || e2.name.toLowerCase().includes(state.filter));
      if (state.parent !== null && state.parent !== undefined) {
        listEl.append(el("button", {
          class: "picker-row", type: "button", onclick: () => navigate(state.parent),
        }, icon("back"), el("span", {}, "… 上一级")));
      }
      if (!entries.length) {
        listEl.append(el("div", { class: "picker-row disabled" }, "（空目录或全部被过滤）"));
      }
      for (const entry of entries) {
        const isSelected =
          state.pickedFile === entry.path || selected.has(entry.path);
        const row = el(
          "button",
          {
            class: "picker-row" + (isSelected ? " selected" : ""),
            type: "button",
            onclick: () => onRow(entry),
          },
          icon(entry.kind === "dir" ? "folder" : "file"),
          el("span", {}, (entry.symlink ? "↗ " : "") + entry.name),
          entry.kind === "file" ? el("span", { class: "size" }, fmtBytes(entry.size)) : null,
        );
        if (entry.kind === "dir" && !entry.navigable) row.classList.add("disabled");
        listEl.append(row);
      }
    }

    function onRow(entry) {
      if (entry.kind === "dir") {
        if (!entry.navigable) { toast("该目录无法访问（根目录限制）", "fail"); return; }
        // 目录始终是“进入”，多选时用下方「选中当前目录」选中目录本身
        navigate(entry.path);
        return;
      }
      // 文件
      if (mode === "dir") { toast("请选择目录：进入目录后按“确定”", "fail"); return; }
      if (mode === "multi") {
        selected.has(entry.path) ? selected.delete(entry.path) : selected.add(entry.path);
      } else {
        state.pickedFile = entry.path; // 单选：高亮，按“确定”生效
      }
      renderList();
    }

    const content = el(
      "div",
      {},
      crumbs,
      shortcutBox,
      el("div", { class: "field-row", style: "margin-bottom:10px" },
        filterInput,
        el("label", { class: "switch", style: "flex:none" }, hiddenInput, el("span", { class: "track" }), el("span", {}, "隐藏文件")),
      ),
      listEl,
      mode === "multi"
        ? el("div", { class: "field-help", style: "margin-top:8px" },
            "点击目录进入；需要选中目录本身时，进入后点「选中当前目录」。")
        : null,
      mode === "out"
        ? el("div", { class: "field", style: "margin-top:14px" },
            el("div", { class: "field-label" }, el("span", {}, "文件名")), outNameInput)
        : null,
      el("div", { class: "form-actions" },
        confirmBtn,
        dirSelectBtn,
        el("button", { class: "btn btn-ghost", type: "button", onclick: () => finish(null) }, "取消")),
    );

    const close = openModal({ title, content, onClose: () => finish(null) });
    navigate(state.path);
  });
}

/* ---------- 表单 ---------- */

const NUM_TYPES = new Set(["int", "float"]);

/* 口令复杂性：≥8 位且至少 3 种字符类型（大小写字母/数字/特殊字符） */
export function pwComplexityOk(pw) {
  if (!pw || pw.length < 8) return false;
  let types = 0;
  if (/[a-z]/.test(pw)) types += 1;
  if (/[A-Z]/.test(pw)) types += 1;
  if (/[0-9]/.test(pw)) types += 1;
  if (/[^A-Za-z0-9]/.test(pw)) types += 1;
  return types >= 3;
}

/* 表单值缓存：同一命令在切换菜单后保留已填内容（内存级；刷新页面即清空） */
const formState = {};

export function commandForm(command, { onSubmit, submitLabel } = {}) {
  const getters = {};
  const dangerFields = [];
  const confirmState = { value: "" }; // keygen 二次确认口令
  const saved = formState[command.name] || (formState[command.name] = {});
  let keygenPwBlock = null; // keygen：已存在密钥时隐藏口令输入
  const save = (name, value) => {
    if (value === null || value === undefined || value === "" || value === false || (Array.isArray(value) && !value.length)) {
      delete saved[name];
    } else {
      saved[name] = value;
    }
  };
  const prev = (f) => (saved[f.name] !== undefined ? saved[f.name] : null);
  const pathInputs = {}; // name → input（供 key-status 等联动）
  const boolInputs = {}; // name → checkbox（keygen 覆盖开关联动）
  let keyStatusEl = null;

  const fieldNode = (f) => {
    const wrap = el("div", { class: "field" + (f.danger ? " danger-field" : "") });
    const label = el("label", { class: "field-label", for: "f-" + f.name },
      el("span", {}, f.label),
      f.required ? el("span", { class: "req" }, "*") : null);
    if (f.danger) label.append(el("span", { class: "badge fail", style: "margin-left:4px" }, "危险"));
    let control;
    let get = () => null;

    if (f.type === "path") {
      const input = el("input", {
        type: "text", id: "f-" + f.name, placeholder: f.placeholder || "",
        value: prev(f) !== null ? String(prev(f)) : (f.default || ""),
        autocomplete: "off", spellcheck: "false",
      });
      pathInputs[f.name] = input;
      input.addEventListener("input", () => save(f.name, input.value.trim() || null));
      control = el("div", { class: "field-row" }, withCopyInside(input),
        el("button", {
          class: "btn btn-ghost btn-sm", type: "button",
          onclick: async () => {
            const picked = await pickPath({
              mode: f.direction === "out" ? "out" : "any",
              title: "选择" + f.label,
              initial: input.value,
            });
            if (picked) {
              input.value = Array.isArray(picked) ? picked[0] : picked;
              input.dispatchEvent(new Event("input")); // 触发缓存与私钥状态刷新
            }
          },
        }, icon("folder"), "浏览…"));
      get = () => input.value.trim() || null;
    } else if (f.type === "paths") {
      const chips = el("div", { class: "chips" });
      const values = prev(f) !== null ? String(prev(f)).split(",") : [];
      const renderChips = () => {
        save(f.name, values.join(","));
        chips.textContent = "";
        values.forEach((v, i) => {
          chips.append(el("span", { class: "chip" }, shortPath(v, 40),
            el("button", { class: "chip-x", type: "button", "aria-label": "移除", onclick: () => { values.splice(i, 1); renderChips(); } }, icon("x"))));
        });
        if (!values.length) chips.append(el("span", { class: "field-help" }, "尚未添加"));
      };
      control = el("div", {},
        chips,
        el("div", { style: "margin-top:8px" },
          el("button", {
            class: "btn btn-ghost btn-sm", type: "button",
            onclick: async () => {
              const picked = await pickPath({ mode: "multi", title: "添加文件或目录", initial: values[values.length - 1] || "" });
              if (Array.isArray(picked)) { picked.forEach((v) => { if (!values.includes(v)) values.push(v); }); renderChips(); }
              else if (picked && !values.includes(picked)) { values.push(picked); renderChips(); }
            },
          }, icon("plus"), "添加文件/目录")));
      get = () => (values.length ? values.slice() : null);
    } else if (f.type === "password") {
      const input = el("input", {
        type: "password", id: "f-" + f.name, placeholder: f.placeholder || "",
        autocomplete: "current-password",
      });
      // 口令不做跨菜单缓存（防止眼睛回看旧口令）
      const pwWrap = withCopyInside(input, { secret: true });
      get = () => input.value || null;
      const parts = [pwWrap];
      if (command.name === "keygen") {
        // 口令复杂性：实时红边提示（规则说明在 placeholder 里，不单独占一行）
        input.addEventListener("input", () => {
          const weak = input.value !== "" && !pwComplexityOk(input.value);
          input.style.borderColor = weak ? "rgba(255,83,112,.55)" : "";
        });
      }
      if (command.fields.some((f2) => f2.name === "key" && f2.type === "path")) {
        // 私钥状态校验：加密/记住/未加密 透明化提示
        keyStatusEl = el("div", { class: "key-status" });
        parts.push(keyStatusEl);
      }
      if (command.name === "keygen") {
        // 设置新口令：二次确认，两次输入不一致时阻止提交
        const confirmId = "f-" + f.name + "-confirm";
        const confirmInput = el("input", {
          type: "password", id: confirmId,
          placeholder: "再次输入口令（留空不加密，不推荐）",
          autocomplete: "new-password",
        });
        const check = () => {
          confirmState.value = confirmInput.value;
          const mismatch =
            (confirmInput.value !== "" && confirmInput.value !== input.value) ||
            (confirmInput.value === "" && input.value !== "");
          confirmInput.style.borderColor = mismatch ? "rgba(255,83,112,.55)" : "";
          confirmInput.setCustomValidity(mismatch ? "两次输入的口令不一致" : "");
        };
        input.addEventListener("input", check);
        confirmInput.addEventListener("input", check);
        parts.push(el("div", { class: "field", style: "margin-top:8px" },
          el("label", { class: "field-label", for: confirmId }, el("span", {}, "确认口令")),
          confirmInput));
      }
      control = el("div", {}, ...parts);
      if (command.name === "keygen") {
        keygenPwBlock = control; // 已存在密钥时由外层控制整体隐藏
      }
    } else if (f.type === "str") {
      const input = el("input", {
        type: "text", id: "f-" + f.name, placeholder: f.placeholder || "",
        autocomplete: "off", spellcheck: "false", value: prev(f) !== null ? String(prev(f)) : "",
      });
      input.addEventListener("input", () => save(f.name, input.value.trim() || null));
      control = input;
      get = () => input.value.trim() || null;
    } else if (f.type === "args") {
      const input = el("input", {
        type: "text", id: "f-" + f.name, placeholder: f.placeholder || "stamp 文件名",
        autocomplete: "off", spellcheck: "false", value: prev(f) !== null ? String(prev(f)) : "",
      });
      input.addEventListener("input", () => save(f.name, input.value.trim() || null));
      control = input;
      get = () => { const v = input.value.trim(); return v ? v.split(/\s+/) : null; };
    } else if (NUM_TYPES.has(f.type)) {
      const input = el("input", {
        type: "number", id: "f-" + f.name,
        min: f.min !== null && f.min !== undefined ? f.min : null,
        max: f.max !== null && f.max !== undefined ? f.max : null,
        step: f.type === "float" ? "any" : "1",
        value: prev(f) !== null ? String(prev(f)) : "",
      });
      input.addEventListener("input", () => save(f.name, input.value === "" ? null : Number(input.value)));
      control = input;
      get = () => (input.value === "" ? null : Number(input.value));
    } else if (f.type === "bool") {
      const input = el("input", {
        type: "checkbox", id: "f-" + f.name,
        checked: prev(f) !== null ? Boolean(prev(f)) : f.default === true,
      });
      boolInputs[f.name] = input;
      input.addEventListener("change", () => save(f.name, input.checked ? true : null));
      control = el("label", { class: "switch", for: "f-" + f.name }, input, el("span", { class: "track" }));
      get = () => (input.checked ? true : null);
      if (f.danger) dangerFields.push(() => input.checked);
    } else if (f.type === "enum") {
      const select = el("select", { id: "f-" + f.name },
        el("option", { value: "" }, "（默认）"),
        f.options.map((o) => el("option", { value: o }, o)));
      if (prev(f) !== null) select.value = String(prev(f));
      select.addEventListener("change", () => save(f.name, select.value || null));
      control = select;
      get = () => select.value || null;
    } else if (f.type === "list") {
      const chips = el("div", { class: "chips" });
      const values = prev(f) !== null ? String(prev(f)).split(",") : [];
      const input = el("input", { type: "text", placeholder: "输入后回车添加，如 *.log", "aria-label": f.label });
      const renderChips = () => {
        save(f.name, values.join(","));
        chips.textContent = "";
        values.forEach((v, i) => {
          chips.append(el("span", { class: "chip" }, v,
            el("button", { class: "chip-x", type: "button", onclick: () => { values.splice(i, 1); renderChips(); } }, icon("x"))));
        });
      };
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          const v = input.value.trim();
          if (v && !values.includes(v)) { values.push(v); input.value = ""; renderChips(); }
        }
      });
      control = el("div", {}, chips, el("div", { style: "margin-top:6px" }, input));
      get = () => (values.length ? values.slice() : null);
    }

    wrap.append(label, control);
    if (f.help) wrap.append(el("div", { class: "field-help" }, f.help));
    getters[f.name] = get;
    return wrap;
  };

  const basic = command.fields.filter((f) => !f.advanced && !f.inline);
  const inlineFields = command.fields.filter((f) => f.inline && !f.advanced);
  const advanced = command.fields.filter((f) => f.advanced);
  const grid = el("div", { class: "form-grid" }, basic.map(fieldNode));
  const form = el("form", {
    class: "form-grid",
    onsubmit: async (e) => {
      e.preventDefault();
      const options = {};
      for (const f of command.fields) {
        const value = getters[f.name]();
        if (value !== null && value !== undefined && value !== false && value !== "") options[f.name] = value;
      }
      if (command.name === "keygen") {
        const pw = options.password || "";
        if (pw !== confirmState.value) {
          toast(pw && !confirmState.value ? "请再次输入口令确认" : "两次输入的口令不一致", "fail");
          return;
        }
        if (pw && !pwComplexityOk(pw)) {
          toast("口令不满足复杂性要求：长度 ≥8 位，且包含大小写字母/数字/特殊字符中的至少 3 种，请修改后再生成", "fail");
          return;
        }
      }
      if (dangerFields.some((fn) => fn())) {
        const okGo = await confirmModal({
          title: "危险选项确认",
          message: "已启用降低校验严格性的选项。可能接受未经完整校验的签名或公钥，请确认你理解其风险。",
          confirmLabel: "仍然执行",
          danger: true,
        });
        if (!okGo) return;
      }
      onSubmit(options);
    },
  });
  form.append(grid);
  if (inlineFields.length) {
    // 横排区：常用可选的开关/输入并排展示，不折叠
    form.append(el("div", { class: "grid-2" }, inlineFields.map(fieldNode)));
  }
  if (advanced.length) {
    const names = advanced.slice(0, 3).map((f) => f.label || f.name).join("、");
    form.append(el("details", { class: "adv" },
      el("summary", {}, `高级选项（${names}${advanced.length > 3 ? " 等" : ""}，共 ${advanced.length} 项）`),
      el("div", { class: "form-grid" }, advanced.map(fieldNode))));
  }
  const actions = el("div", { class: "form-actions" },
    el("button", { class: "btn btn-primary", type: "submit" }, submitLabel || command.title),
    el("span", { class: "form-note" },
      command.mutating ? "该操作会写入文件" : "只读操作，不会修改任何文件"));
  form.append(actions);

  // bundle / unpack：根据输入自动建议输出路径（用户手动改过后不再覆盖）
  if (command.name === "bundle" && pathInputs["dir"] && pathInputs["output"]) {
    let auto = pathInputs["output"].value.trim();
    const suggest = () => {
      const dir = pathInputs["dir"].value.trim();
      const out = pathInputs["output"];
      if (!dir) return;
      const guess = joinPath(dirname(dir), basename(dir) + ".zip");
      if (!out.value.trim() || out.value === auto) {
        out.value = guess;
        auto = guess;
        out.dispatchEvent(new Event("input"));
      }
    };
    pathInputs["dir"].addEventListener("input", suggest);
  }
  if (command.name === "sbom" && pathInputs["dir"] && pathInputs["output"]) {
    let auto = pathInputs["output"].value.trim();
    const suggest = () => {
      const dir = pathInputs["dir"].value.trim();
      const out = pathInputs["output"];
      if (!dir) return;
      const name = basename(dir);
      if (!name || name === "." || name === "..") return;
      const guess = joinPath(dirname(dir), name + ".cdx.json");
      if (!out.value.trim() || out.value === auto) {
        out.value = guess;
        auto = guess;
        out.dispatchEvent(new Event("input"));
      }
    };
    pathInputs["dir"].addEventListener("input", suggest);
    suggest();
  }
  if (command.name === "unpack" && pathInputs["bundle"] && pathInputs["dest"]) {
    let auto = pathInputs["dest"].value.trim();
    const suggest = () => {
      const bundle = pathInputs["bundle"].value.trim();
      const dest = pathInputs["dest"];
      if (!bundle) return;
      const name = basename(bundle).replace(/\.zip$/i, "") || "bundle";
      const guess = joinPath(dirname(bundle), name);
      if (!dest.value.trim() || dest.value === auto) {
        dest.value = guess;
        auto = guess;
        dest.dispatchEvent(new Event("input"));
      }
    };
    pathInputs["bundle"].addEventListener("input", suggest);
  }

  // keygen：已存在密钥 → 隐藏口令输入（防止他人通过眼睛窥视）；
  // 勾选「覆盖已有密钥」替换时恢复显示，可设置新口令。
  if (command.name === "keygen" && keygenPwBlock && boolInputs["force"] && pathInputs["private"]) {
    const note = el("div", {
      class: "key-status warn", style: "display:none",
    }, "已存在密钥：已隐藏口令输入；勾选「覆盖已有密钥」替换时可设置新口令");
    keygenPwBlock.parentNode.insertBefore(note, keygenPwBlock);
    keygenPwBlock.style.display = "none";
    let existTimer = null;
    let keyExists = false;
    const refresh = async () => {
      const target = pathInputs["private"].value.trim();
      keyExists = false;
      if (target) {
        try {
          const info = await api.keyInfo(target);
          keyExists = info.exists !== false;
        } catch { keyExists = false; }
      }
      const showPw = !keyExists || boolInputs["force"].checked;
      keygenPwBlock.style.display = showPw ? "" : "none";
      note.style.display = showPw || !keyExists ? "none" : "";
    };
    pathInputs["private"].addEventListener("input", () => {
      clearTimeout(existTimer);
      existTimer = setTimeout(refresh, 350);
    });
    boolInputs["force"].addEventListener("change", refresh);
    refresh();
  }

  // 私钥状态校验联动（sign / attest）：私钥路径变化 → 检查加密与口令记忆
  const keyInput = pathInputs["key"];
  if (keyStatusEl && keyInput) {
    let timer = null;
    const updateKeyStatus = async () => {
      const value = keyInput.value.trim();
      if (!value) {
        keyStatusEl.className = "key-status";
        keyStatusEl.textContent = "";
        return;
      }
      keyStatusEl.className = "key-status";
      keyStatusEl.textContent = "检查私钥…";
      try {
        const info = await api.keyInfo(value);
        if (!keyStatusEl.isConnected) return;
        if (info.exists === false) {
          keyStatusEl.className = "key-status err";
          keyStatusEl.textContent = "私钥不存在或无法读取";
        } else if (info.encrypted && info.remembered) {
          keyStatusEl.className = "key-status ok";
          keyStatusEl.textContent = "私钥已加密 · 口令已记住，可直接签名";
        } else if (info.encrypted) {
          keyStatusEl.className = "key-status warn";
          keyStatusEl.textContent = "私钥已加密 · 需要输入口令";
        } else {
          keyStatusEl.className = "key-status warn";
          keyStatusEl.textContent = "私钥未加密（建议加密后使用）";
        }
      } catch {
        if (!keyStatusEl.isConnected) return;
        keyStatusEl.className = "key-status err";
        keyStatusEl.textContent = "私钥不存在或无法读取";
      }
    };
    keyInput.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(updateKeyStatus, 350);
    });
    if (keyInput.value.trim()) updateKeyStatus();
  }

  return form;
}

/* ---------- 结果渲染 ---------- */

function kvRow(key, value, mono = false) {
  return [el("div", { class: "k" }, key), el("div", { class: "v" + (mono ? " mono" : "") }, value)];
}

function copyRow(text, display) {
  return el("button", {
    class: "inline-copy", type: "button",
    onclick: () => copyText(text),
  }, icon("copy"), display || shortPath(text, 36));
}

function warningsBox(warnings) {
  if (!warnings || !warnings.length) return null;
  return el("ul", { class: "warn-list" }, warnings.slice(0, 20).map((w) => el("li", {}, w)));
}

function tableOf(headers, rows, cap = 300) {
  return el("div", { class: "table-wrap" },
    el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
      el("tbody", {}, rows.slice(0, cap).map((cells) => el("tr", {}, cells.map((c) => el("td", { class: c && c.mono ? "mono" : "" }, c && c.text !== undefined ? c.text : c)))))));
}

function verifyResultCard(task) {
  const r = task.result || {};
  const kids = [];
  const ok = r.ok;
  kids.push(el("div", {
    class: "banner " + (ok ? "ok" : "fail"),
  },
    icon(ok ? "check" : "alert"),
    el("div", {},
      el("strong", {}, ok ? "验证通过" : "验证未通过"),
      el("div", { class: "sub" },
        ok ? "内容与签名一致，且签名来自该公钥对应的私钥。" : "文件与签名不匹配，或元数据被改动。详见下方原因。"))));
  const kv = el("div", { class: "kv" });
  const expected = r.expected || {};
  kv.append(...kvRow("目标", r.target || task.result.file || "—"));
  kv.append(...kvRow("公钥指纹", copyRow(r.signer_fingerprint || "—", r.signer_fingerprint || "—"), true));
  kv.append(...kvRow("SHA-256", copyRow(r.digest || "—", r.digest || "—"), true));
  kv.append(...kvRow("大小", fmtBytes(r.size)));
  if (expected.name) kv.append(...kvRow("签名名称", expected.name));
  if (expected.signer !== undefined) kv.append(...kvRow("签名者", expected.signer || "（未填写）"));
  if (expected.created) kv.append(...kvRow("签名时间", fmtTime(expected.created)));
  if (r.timestamp) {
    if (r.timestamp.ok) {
      kv.append(...kvRow("时间戳", `✅ ${fmtTime(r.timestamp.gen_time)} 由 ${r.timestamp.tsa} 见证（证书链: ${r.timestamp.chain}）`));
    } else {
      kv.append(...kvRow("时间戳", `❌ ${r.timestamp.error || "校验失败"}`));
    }
  }
  kids.push(kv);
  if (r.reasons && r.reasons.length) {
    kids.push(el("ul", { class: "warn-list", style: "border-color:rgba(229,5,9,.3);background:rgba(229,5,9,.05);color:var(--danger-text)" },
      r.reasons.map((x) => el("li", {}, x))));
  }
  const files = r.files;
  if (files) {
    const chips = el("div", { class: "chips", style: "margin-top:14px" },
      el("span", { class: "badge info" }, `清单内 ${files.checked} 个文件`),
      el("span", { class: "badge " + (files.failed && files.failed.length ? "fail" : "ok") }, `失败 ${files.failed ? files.failed.length : 0}`),
      el("span", { class: "badge " + (files.unlisted && files.unlisted.length ? "warn" : "info") }, `未列入 ${files.unlisted ? files.unlisted.length : 0}`));
    kids.push(chips);
    if (files.failed && files.failed.length) {
      kids.push(el("div", { style: "margin-top:12px" },
        tableOf(["文件", "原因"], files.failed.map((f2) => [f2.path, f2.reason]), 100)));
    }
    if (files.unlisted && files.unlisted.length) {
      kids.push(el("div", { class: "chips", style: "margin-top:12px" },
        files.unlisted.slice(0, 30).map((u) => el("span", { class: "chip" }, u))));
    }
  }
  return kids;
}

function statusResultCard(task) {
  const r = task.result || {};
  const ok = r.ok;
  const kids = [el("div", { class: "banner " + (ok ? "ok" : "fail") },
    icon(ok ? "check" : "alert"),
    el("div", {},
      el("strong", {}, ok ? "检查通过" : "检查未通过"),
      el("div", { class: "sub" }, r.signature_ok ? "签名有效（未请求 TSA）" : "签名无效")))];
  const kv = el("div", { class: "kv" });
  kv.append(...kvRow("目标", r.target || r.path || "—"));
  kv.append(...kvRow("结果", ok ? "✅ 通过" : "❌ 未通过"));
  if (r.checked !== undefined) kv.append(...kvRow("清单内文件", `${r.checked} 个`));
  kids.push(kv);
  if (r.failed && r.failed.length) kids.push(tableOf(["文件", "原因"], r.failed.map((f2) => [f2.path, f2.reason]), 100));
  if (r.unlisted && r.unlisted.length) kids.push(el("div", { class: "chips", style: "margin-top:12px" }, r.unlisted.slice(0, 30).map((u) => el("span", { class: "chip" }, u))));
  return kids;
}

function genericKv(result, skip = new Set()) {
  const kv = el("div", { class: "kv" });
  for (const [key, value] of Object.entries(result || {})) {
    if (skip.has(key) || value === null || value === undefined) continue;
    if (typeof value === "boolean") { kv.append(...kvRow(key, value ? "是" : "否")); continue; }
    if (typeof value === "object") continue;
    const mono = typeof value === "string" && /^[A-Fa-f0-9]{64}$/.test(value);
    kv.append(...kvRow(key, mono ? copyRow(value, value) : String(value), true));
  }
  return kv;
}

export function taskResult(command, task) {
  const kids = [];
  const r = task.result || {};
  const partialSign = command === "sign" && task.state === "failed"
    && (r.items || []).length > 0 && !r.cancelled;
  if (partialSign) {
    kids.push(el("div", { class: "banner warn" }, icon("alert"),
      el("div", {},
        el("strong", {}, "签名已生成，但时间戳未完成"),
        el("div", { class: "sub" },
          "签名文件仍然有效。安装 OpenSSL 后可在「时间戳与证明 → 续期时间戳」重试；" +
          "或在高级选项中关闭时间戳后重新签名。"))));
  } else if (task.state === "failed") {
    kids.push(el("div", { class: "banner fail" }, icon("alert"),
      el("div", {}, el("strong", {}, "执行失败"), task.error ? el("div", { class: "sub" }, task.error) : null)));
  } else if (task.state === "canceled") {
    kids.push(el("div", { class: "banner warn" }, icon("alert"),
      el("div", {}, el("strong", {}, "已取消"), task.error ? el("div", { class: "sub" }, task.error) : null)));
  } else {
    kids.push(el("div", { class: "banner ok" }, icon("check"),
      el("div", {}, el("strong", {}, "执行成功"), el("div", { class: "sub" }, `退出码 ${task.rc ?? 0}`))));
  }

  if (command === "verify") kids.push(...verifyResultCard(task));
  else if (command === "status") kids.push(...statusResultCard(task));
  else if (command === "sign") {
    const items = r.items || [];
    if (items.length) {
      kids.push(tableOf(["目标", "签名文件", "SHA-256", "大小", "时间戳"],
        items.map((it) => [
          { text: it.path, mono: true },
          { text: it.sig, mono: true },
          { text: it.digest, mono: true },
          fmtBytes(it.size),
          it.timestamp ? `✅ ${fmtTime(it.timestamp.gen_time)}` : "—",
        ])));
    }
    if (r.cancelled) kids.push(el("div", { class: "banner warn", style: "margin-top:12px" }, icon("alert"), el("div", {}, "已取消：剩余目标未处理")));
  } else if (command === "hash") {
    const files = r.files || [];
    if (files.length) {
      kids.push(tableOf(["SHA-256", "文件", "大小"],
        files.map((f2) => [{ text: f2.digest, mono: true }, { text: f2.path, mono: true }, fmtBytes(f2.size)])));
      kids.push(el("div", { style: "margin-top:10px" },
        copyRow(files.map((f2) => `${f2.digest}  ${f2.path}`).join("\n"), "复制全部校验和")));
    }
  } else if (command === "keygen") {
    kids.push(el("div", { class: "kv" },
      ...kvRow("私钥", r.private || "—"),
      ...kvRow("公钥", r.public || "—"),
      ...kvRow("加密", r.encrypted ? "是" : "否（未加密，注意保管）"),
      ...kvRow("公钥指纹", copyRow(r.fingerprint || "—", r.fingerprint || "—"), true)));
    kids.push(el("div", { class: "banner warn", style: "margin-top:12px" }, icon("alert"),
      el("div", {}, "下一步：把公钥和指纹通过“与文件不同的可信渠道”交给对方核对。")));
  } else if (command === "fingerprint") {
    kids.push(el("div", { class: "kv" }, ...kvRow("公钥", r.key || "—"), ...kvRow("指纹", copyRow(r.fingerprint || "—", r.fingerprint || "—"), true)));
    kids.push(el("p", { class: "field-help", style: "margin-top:8px" }, "请通过电话/当面等独立渠道核对该指纹，防中间人。"));
  } else if (command === "timestamp" || command === "renew") {
    kids.push(genericKv(r, new Set(["ok"])));
  } else if (command === "diff") {
    const chips = el("div", { class: "chips", style: "margin-bottom:12px" },
      el("span", { class: "badge " + ((r.added || []).length ? "warn" : "info") }, `新增 ${(r.added || []).length}`),
      el("span", { class: "badge " + ((r.removed || []).length ? "warn" : "info") }, `删除 ${(r.removed || []).length}`),
      el("span", { class: "badge " + ((r.changed || []).length ? "fail" : "info") }, `变化 ${(r.changed || []).length}`));
    kids.push(chips);
    for (const [key, mark] of [["added", "+"], ["removed", "-"], ["changed", "~"]]) {
      const list = r[key] || [];
      if (list.length) kids.push(tableOf([key], list.map((x) => ({ text: `${mark} ${x}`, mono: true }))));
    }
  } else if (command === "ots") {
    kids.push(el("div", { class: "banner " + (r.ok ? "ok" : "fail") }, icon(r.ok ? "check" : "alert"),
      el("div", {}, el("strong", {}, r.ok ? "ots 执行成功" : `ots 退出码 ${r.rc}`))));
  } else {
    kids.push(genericKv(r, new Set(["ok", "cancelled"])));
  }

  const box = el("div", {},
    warningsBox(task.warnings),
    ...kids);
  return box;
}
