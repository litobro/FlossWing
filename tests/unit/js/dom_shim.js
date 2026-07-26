// FlossWing -- local-CLI vulnerability research harness.
// Copyright (C) 2026  FlossWing contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Deny-by-default DOM shim for tests/unit/test_report_html_js.py.
//
// This is NOT a general-purpose DOM implementation. It models only the
// exact surface flosswing/stages/report_html.py's `_JS` legitimately uses
// (see the `ALLOWED_GET` / `ALLOWED_SET` comments below, derived by reading
// `_JS` itself) and throws a descriptive Error for anything else -- property
// read, property write, or method call. That is the whole point: a
// source-grep blocklist can only catch sink names someone thought to name
// (it already missed `setHTMLUnsafe` once -- a reviewer swapped it in for
// `textContent` and the entire suite stayed green). This shim instead
// enumerates the *safe* surface and denies everything outside it, so any
// markup-parsing sink -- enumerated or not -- fails by construction.
//
// Node built-ins only. No npm, no package.json, no external module.
"use strict";

// Elements created by document.createElement() are represented internally
// as a plain "raw" object (never exposed to script code) plus a Proxy over
// it (what script code actually holds). RAW maps a proxy back to its raw
// node so trusted shim code (appendChild, querySelectorAll, the serializer)
// can walk the real tree without going through the deny-by-default trap.
const RAW = new WeakMap();

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function newRawNode(tag) {
  return {
    tag: String(tag),
    className: "",
    textContent: null,
    type: null,
    hidden: false,
    attrs: new Map(),
    dataset: Object.create(null),
    children: [],
    listeners: Object.create(null),
  };
}

function rawOf(value) {
  const raw = RAW.get(value);
  if (!raw) {
    throw new Error(
      "dom_shim: expected a node created via document.createElement(), got " + String(value)
    );
  }
  return raw;
}

// dataset -- _JS only ever assigns/reads `.dataset.status`. Anything else
// is denied, matching the "derive the allowlist from what _JS actually
// does" design rule.
function datasetProxy(raw) {
  return new Proxy(raw.dataset, {
    get(target, prop) {
      if (prop === "status") return target.status;
      throw new Error(
        `dom_shim: DENIED read of dataset.${String(prop)} -- only 'status' is modeled`
      );
    },
    set(target, prop, value) {
      if (prop !== "status") {
        throw new Error(
          `dom_shim: DENIED write of dataset.${String(prop)} -- only 'status' is modeled`
        );
      }
      target.status = String(value);
      return true;
    },
  });
}

// classList -- _JS only ever calls `.classList.toggle(name)`.
function classListProxy(raw) {
  return new Proxy(Object.create(null), {
    get(_target, prop) {
      if (prop === "toggle") {
        return (name) => {
          const tokens = new Set(raw.className.split(/\s+/).filter(Boolean));
          let nowPresent;
          if (tokens.has(name)) {
            tokens.delete(name);
            nowPresent = false;
          } else {
            tokens.add(name);
            nowPresent = true;
          }
          raw.className = [...tokens].join(" ");
          return nowPresent;
        };
      }
      throw new Error(`dom_shim: DENIED classList.${String(prop)} -- not in allowlist`);
    },
    set(_target, prop) {
      throw new Error(`dom_shim: DENIED write to classList.${String(prop)}`);
    },
  });
}

// querySelectorAll -- _JS only ever uses a single class selector ('.chip',
// '.f'). Real CSS selector support is out of scope for this shim.
function matchesSelector(raw, selector) {
  if (typeof selector === "string" && selector.startsWith(".")) {
    const cls = selector.slice(1);
    return raw.className.split(/\s+/).includes(cls);
  }
  throw new Error(`dom_shim: querySelectorAll('${selector}') -- only '.class' is modeled`);
}

function queryAll(rootRaw, selector) {
  const out = [];
  const walk = (raw) => {
    for (const child of raw.children) {
      if (matchesSelector(child, selector)) out.push(wrap(child));
      walk(child);
    }
  };
  walk(rootRaw);
  return out;
}

// The full allowed element surface. Everything not listed here throws.
// Settable properties: className, textContent, type, hidden (plus the
// nested dataset.status / classList.toggle proxies above).
// Callable methods: appendChild, setAttribute, addEventListener,
// querySelectorAll, plus the dataset/classList getters.
function wrap(raw) {
  const proxy = new Proxy(raw, {
    get(target, prop) {
      switch (prop) {
        case "className":
          return target.className;
        case "textContent":
          return target.textContent;
        case "type":
          return target.type;
        case "hidden":
          return target.hidden;
        case "dataset":
          return datasetProxy(target);
        case "classList":
          return classListProxy(target);
        case "appendChild":
          return (child) => {
            target.children.push(rawOf(child));
            return child;
          };
        case "setAttribute":
          return (name, value) => {
            const attrName = String(name);
            if (/^on/i.test(attrName)) {
              throw new Error(
                `dom_shim: DENIED setAttribute('${attrName}', ...) -- event-handler-like ` +
                  "attribute"
              );
            }
            target.attrs.set(attrName, String(value));
          };
        case "addEventListener":
          return (type, handler) => {
            (target.listeners[type] ||= []).push(handler);
          };
        case "querySelectorAll":
          return (selector) => queryAll(target, selector);
        default:
          throw new Error(
            `dom_shim: DENIED read of <${target.tag}>.${String(prop)} -- not an allowed DOM ` +
              "surface (this is exactly the class of bug this shim exists to catch)"
          );
      }
    },
    set(target, prop, value) {
      switch (prop) {
        case "className":
          target.className = String(value);
          return true;
        case "textContent":
          // The real DOM's textContent setter replaces all children with a
          // single text node; model that so a node can never carry both
          // trusted structure and untrusted "text" that later gets treated
          // as structure.
          target.textContent = value === null || value === undefined ? null : String(value);
          target.children = [];
          return true;
        case "type":
          target.type = String(value);
          return true;
        case "hidden":
          target.hidden = Boolean(value);
          return true;
        default:
          throw new Error(
            `dom_shim: DENIED write to <${target.tag}>.${String(prop)} -- markup/unknown sink ` +
              "not in allowlist (this is exactly the class of bug this shim exists to catch)"
          );
      }
    },
  });
  RAW.set(proxy, raw);
  return proxy;
}

function createElement(tag) {
  return wrap(newRawNode(tag));
}

// document -- only getElementById('app'), createElement(), and title= are
// modeled; _JS uses nothing else on `document`.
function makeDocument(appRaw) {
  const docState = { title: "" };
  return new Proxy(docState, {
    get(target, prop) {
      if (prop === "getElementById") {
        return (id) => {
          if (id === "app") return wrap(appRaw);
          throw new Error(`dom_shim: DENIED getElementById('${id}') -- only '#app' is modeled`);
        };
      }
      if (prop === "createElement") return (tag) => createElement(tag);
      if (prop === "title") return target.title;
      throw new Error(`dom_shim: DENIED read of document.${String(prop)} -- not in allowlist`);
    },
    set(target, prop, value) {
      if (prop === "title") {
        target.title = String(value);
        return true;
      }
      throw new Error(`dom_shim: DENIED write of document.${String(prop)} -- not in allowlist`);
    },
  });
}

// Renders the *real* tree (raw nodes, bypassing every Proxy) to a string,
// HTML-escaping text nodes. If a hostile finding field ever reached the DOM
// as markup instead of text, it would show up here as an actual `<img`/
// `<script`/`<svg` open tag or an `on*=` attribute rather than as escaped
// text -- visibly distinguishable, which is the whole point of requirement
// 3: this must never parse markup, only render it as inert characters.
function serialize(raw) {
  let out = `<${raw.tag}`;
  if (raw.className) out += ` class="${escapeHtml(raw.className)}"`;
  if (raw.type) out += ` type="${escapeHtml(raw.type)}"`;
  if (raw.hidden) out += " hidden";
  for (const [name, value] of raw.attrs) {
    out += ` ${escapeHtml(name)}="${escapeHtml(value)}"`;
  }
  if (raw.dataset && raw.dataset.status !== undefined) {
    out += ` data-status="${escapeHtml(raw.dataset.status)}"`;
  }
  out += ">";
  if (raw.textContent !== null && raw.textContent !== undefined) {
    out += escapeHtml(raw.textContent);
  }
  for (const child of raw.children) {
    out += serialize(child);
  }
  out += `</${raw.tag}>`;
  return out;
}

const __APP_RAW__ = newRawNode("main");
const document = makeDocument(__APP_RAW__); // eslint-disable-line no-unused-vars
function __shim_serialize__() {
  return serialize(__APP_RAW__);
}
