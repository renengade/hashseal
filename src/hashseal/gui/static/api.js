/* API 客户端：token 管理、请求封装、任务轮询 */

const TOKEN_KEY = "hashseal.token";

export function initToken() {
  const match = location.hash.match(/^#token=(.+)$/);
  if (match) {
    sessionStorage.setItem(TOKEN_KEY, decodeURIComponent(match[1]));
    history.replaceState(null, "", "#/");
    return true;
  }
  return Boolean(sessionStorage.getItem(TOKEN_KEY));
}

export function hasToken() {
  return Boolean(sessionStorage.getItem(TOKEN_KEY));
}

export class ApiFail extends Error {
  constructor(err, status) {
    super((err && err.message) || "请求失败");
    this.code = (err && err.code) || "error";
    this.hint = err && err.hint;
    this.status = status;
  }
}

async function request(path, opts = {}) {
  const headers = { "X-Hashseal-Token": sessionStorage.getItem(TOKEN_KEY) || "" };
  let body;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  let res;
  try {
    res = await fetch(path, { method: opts.method || "GET", headers, body });
  } catch {
    throw new ApiFail({ code: "network", message: "无法连接到 hashseal 服务" }, 0);
  }
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent("hashseal:unauthorized"));
    throw new ApiFail({ code: "unauthorized", message: "会话无效，请使用终端中的新地址打开" }, 401);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiFail(data.error || {}, res.status);
  return data;
}

export const api = {
  status: () => request("/api/status"),
  commands: () => request("/api/commands"),
  config: () => request("/api/config"),
  browse: (path, hidden) =>
    request("/api/browse?hidden=" + (hidden ? "1" : "0") + (path ? "&path=" + encodeURIComponent(path) : "")),
  keyInfo: (key) => request("/api/key-info?key=" + encodeURIComponent(key)),
  audit: (lines) => request("/api/audit?lines=" + lines),
  vault: () => request("/api/vault"),
  unlock: (key, password) => request("/api/vault/unlock", { method: "POST", body: { key, password } }),
  lock: (key) => request("/api/vault/lock", { method: "POST", body: key ? { key } : {} }),
  run: (command, options) => request("/api/run", { method: "POST", body: { command, options } }),
  task: (id) => request("/api/tasks/" + id),
  cancel: (id) => request(`/api/tasks/${id}/cancel`, { method: "POST", body: {} }),
  shutdown: () => request("/api/shutdown", { method: "POST", body: {} }),
};

const TERMINAL = ["succeeded", "failed", "canceled"];

/** 提交任务并轮询到终态；onTask 在每次轮询时回调（渲染进度）。 */
export async function runTask(command, options, onTask) {
  const { task_id } = await api.run(command, options);
  let delay = 400;
  for (;;) {
    const task = await api.task(task_id);
    if (onTask) onTask(task);
    if (TERMINAL.includes(task.state)) return task;
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(1000, delay + 120);
  }
}
