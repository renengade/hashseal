// 最小 DOM 垫片：在 Node 中执行 ui.js 的 commandForm/taskResult，
// 用于捕获“渲染崩溃导致空白页”这类回归（无浏览器依赖）。
import { readFileSync } from "node:fs";

class FakeNode {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.style = {};
    this.dataset = {};
    this.classList = {
      add() {}, remove() {}, toggle() {}, contains() { return false; },
    };
    this.parentNode = null;
    this._attrs = {};
  }
  append(...kids) {
    for (const kid of kids.flat(9)) {
      if (kid == null || kid === false) continue;
      if (kid.nodeType || kid.appendChild) {
        kid.parentNode = this;
        this.children.push(kid);
      }
    }
    return this;
  }
  appendChild(kid) { return this.append(kid); }
  setAttribute(key, value) {
    this._attrs[key] = value;
    if (key === "id") this.id = value;
    if (key === "value") this.value = value;
    if (key === "checked") this.checked = value === "" || value === true;
    if (key === "class") this.className = value;
  }
  addEventListener() {}
  insertBefore(node) { node.parentNode = this; return node; }
  remove() { this.parentNode = null; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  cloneNode() { return new FakeNode(this.tagName); }
  get textContent() { return this._text || ""; }
  set textContent(value) { this._text = value; this.children = []; }
  get isConnected() { return true; }
}

globalThis.document = {
  createElement: (tag) => new FakeNode(tag),
  createElementNS: (_ns, tag) => new FakeNode(tag),
  createTextNode: (text) => {
    const node = new FakeNode("#text");
    node._text = text;
    return node;
  },
  getElementById: () => new FakeNode("div"),
  addEventListener() {},
  body: new FakeNode("body"),
};
globalThis.sessionStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
globalThis.location = { hash: "", replaceState() {} };
globalThis.history = { replaceState() {} };

const specs = JSON.parse(readFileSync(process.argv[2], "utf-8"));
const ui = await import("./ui.js");

let failures = 0;
for (const command of specs) {
  try {
    ui.commandForm(command, { onSubmit() {} });
  } catch (error) {
    failures += 1;
    console.error(`FORM FAIL ${command.name}: ${error && error.stack ? error.stack.split("\n")[0] : error}`);
  }
}

const tasks = [
  {
    command: "sign", state: "succeeded", rc: 0, error: null, warnings: [],
    result: {
      items: [{
        path: "C:\\Users\\me\\a.txt", sig: "C:\\Users\\me\\a.txt.sig",
        digest: "a".repeat(64), size: 3,
        timestamp: { gen_time: "2026-01-01T00:00:00+00:00", tsa: "Test TSA", chain: "ok" },
      }],
      cancelled: false,
    },
  },
  {
    command: "sign", state: "failed", rc: 1, error: null,
    warnings: ["时间戳失败"],
    result: { items: [{ path: "x", sig: "x.sig", digest: "b".repeat(64), size: 2 }], cancelled: false },
  },
  {
    command: "verify", state: "failed", rc: 1, error: "失败", warnings: [],
    result: {
      ok: false, target: "C:\\f", kind: "file", signature_valid: false,
      metadata_valid: true, digest: "c".repeat(64), size: 3,
      expected: { name: "f", size: 3, digest: "c".repeat(64), signer: "", created: "2026-01-01T00:00:00+00:00" },
      signer_fingerprint: "SHA256:test", reasons: ["内容不一致"], timestamp: null,
    },
  },
  {
    command: "hash", state: "succeeded", rc: 0, error: null, warnings: [],
    result: { files: [{ path: "a", digest: "d".repeat(64), size: 1 }], count: 1, cancelled: false },
  },
];
for (const task of tasks) {
  try {
    ui.taskResult(task.command, task);
  } catch (error) {
    failures += 1;
    console.error(`RESULT FAIL ${task.command}/${task.state}: ${error && error.stack ? error.stack.split("\n")[0] : error}`);
  }
}

if (failures) {
  console.error(`${failures} 个渲染失败`);
  process.exit(1);
}
console.log(`OK ${specs.length} forms + ${tasks.length} results`);
