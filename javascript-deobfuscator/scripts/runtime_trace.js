#!/usr/bin/env node
/*
Offline JavaScript runtime trace harness.

This is a triage aid, not a security sandbox. Run only on authorized local
samples. Network primitives are stubbed and logged instead of executed.
*/

const fs = require("fs");
const vm = require("vm");

function parseArgs(argv) {
  const args = { out: "runtime_trace.json", timeout: 1000 };
  for (let i = 2; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === "--out") {
      args.out = argv[++i];
    } else if (item === "--timeout") {
      args.timeout = Number(argv[++i]);
    } else if (!args.file) {
      args.file = item;
    }
  }
  if (!args.file) {
    console.error("Usage: node runtime_trace.js <file.js> [--out trace.json] [--timeout 1000]");
    process.exit(2);
  }
  return args;
}

function redact(value) {
  let text = typeof value === "string" ? value : JSON.stringify(value);
  if (text === undefined) text = String(value);
  text = text.replace(/sk_(?:live|test)_[A-Za-z0-9_-]{10,}/gi, "<redacted>");
  text = text.replace(/sk\d?_[A-Za-z0-9_-]{12,}/gi, "<redacted>");
  text = text.replace(/gh[pousr]_[A-Za-z0-9_]{20,}/gi, "<redacted>");
  text = text.replace(/xox[baprs]-[A-Za-z0-9-]{20,}/gi, "<redacted>");
  text = text.replace(/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "<redacted>");
  text = text.replace(/([?&](?:token|access_token|refresh_token|api_key|apikey|key|secret|password|auth|authorization|code|license)=)[^&"'\\\s]+/gi, "$1<redacted>");
  text = text.replace(/((?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|authorization|license)["']?\s*[:=]\s*["'])([^"']{4,})(["'])/gi, "$1<redacted>$3");
  return text.length > 5000 ? `${text.slice(0, 5000)}...<truncated>` : text;
}

function main() {
  const args = parseArgs(process.argv);
  const code = fs.readFileSync(args.file, "utf8");
  const events = [];
  const log = (type, detail) => events.push({ type, detail, ts: new Date().toISOString() });

  class StubXHR {
    open(method, url) {
      log("XMLHttpRequest.open", { method: redact(method), url: redact(url) });
    }
    setRequestHeader(key, value) {
      log("XMLHttpRequest.setRequestHeader", { key: redact(key), value: redact(value) });
    }
    send(body) {
      log("XMLHttpRequest.send", { body: redact(body || "") });
    }
  }

  const storage = {
    getItem(key) {
      log("storage.getItem", { key: redact(key) });
      return null;
    },
    setItem(key, value) {
      log("storage.setItem", { key: redact(key), value: redact(value) });
    },
    removeItem(key) {
      log("storage.removeItem", { key: redact(key) });
    },
  };

  const sandbox = {
    console: {
      log: (...items) => log("console.log", items.map(redact)),
      warn: (...items) => log("console.warn", items.map(redact)),
      error: (...items) => log("console.error", items.map(redact)),
    },
    atob(input) {
      const output = Buffer.from(String(input), "base64").toString("utf8");
      log("atob", { input: redact(input), output: redact(output) });
      return output;
    },
    btoa(input) {
      const output = Buffer.from(String(input), "utf8").toString("base64");
      log("btoa", { input: redact(input), output: redact(output) });
      return output;
    },
    eval(payload) {
      log("eval", { payload: redact(payload) });
      return undefined;
    },
    Function: function (...args) {
      log("Function", { args: args.map(redact) });
      return function noop() {};
    },
    fetch(url, options) {
      log("fetch", { url: redact(url), options: redact(options || {}) });
      return Promise.resolve({ ok: false, status: 0, text: async () => "", json: async () => ({}) });
    },
    XMLHttpRequest: StubXHR,
    localStorage: storage,
    sessionStorage: storage,
    document: {
      cookie: "",
      createElement: () => ({}),
      querySelector: () => null,
      getElementById: () => null,
    },
    navigator: { userAgent: "offline-trace" },
    location: { href: "http://localhost/offline", origin: "http://localhost" },
    crypto: {
      subtle: {
        decrypt(...items) {
          log("crypto.subtle.decrypt", { args: items.map(redact) });
          return Promise.reject(new Error("disabled in offline trace"));
        },
        importKey(...items) {
          log("crypto.subtle.importKey", { args: items.map(redact) });
          return Promise.reject(new Error("disabled in offline trace"));
        },
      },
    },
    setTimeout,
    clearTimeout,
    Buffer,
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;

  try {
    vm.createContext(sandbox);
    vm.runInContext(code, sandbox, { timeout: args.timeout });
  } catch (error) {
    log("runtime.error", { message: redact(error.message) });
  }

  fs.writeFileSync(args.out, JSON.stringify({ file: args.file, events }, null, 2), "utf8");
  console.log(`[+] Trace events: ${events.length}`);
  console.log(`[+] Output: ${args.out}`);
}

main();
