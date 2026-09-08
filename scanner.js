#!/usr/bin/env node

import { chromium } from "playwright";
import chalk from "chalk";
import fs from "node:fs/promises";
import path from "node:path";
import readline from "node:readline";
import { performance } from "node:perf_hooks";

const VERSION = "1.0.0";

/*
 * ============================================================
 *  WEBS CAN
 *  Authorized website intelligence / passive scanner
 * ============================================================
 *
 *  Features:
 *   - Interactive CLI
 *   - Same-origin crawling
 *   - Browser network observation
 *   - Observed endpoint discovery
 *   - Request/response headers
 *   - Security headers
 *   - Cookies
 *   - localStorage/sessionStorage
 *   - Forms
 *   - Scripts/styles/images
 *   - Metadata
 *   - robots.txt
 *   - sitemap.xml
 *   - External domains
 *   - Basic technology detection
 *   - JSON + HTML reports
 *
 *  Only scan websites you own or have permission to assess.
 * ============================================================
 */

const C = {
  cyan: chalk.hex("#00E5FF"),
  blue: chalk.hex("#4D7CFE"),
  purple: chalk.hex("#A855F7"),
  pink: chalk.hex("#EC4899"),
  green: chalk.hex("#22C55E"),
  yellow: chalk.hex("#FACC15"),
  red: chalk.hex("#EF4444"),
  white: chalk.hex("#F8FAFC"),
  gray: chalk.hex("#64748B"),
  dim: chalk.dim,
  bold: chalk.bold
};

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function clear() {
  process.stdout.write("\x1Bc");
}

function line(char = "─", width = 68) {
  return C.gray(char.repeat(width));
}

function banner() {
  console.log();
  console.log(
    C.cyan("     ██     ██ ███████ ██████   ██████  ██████   █████  ███    ██")
  );
  console.log(
    C.cyan("     ██     ██ ██      ██   ██ ██      ██       ██   ██ ████   ██")
  );
  console.log(
    C.purple("     ██  █  ██ █████   ██████  ██      ██   ███ ███████ ██ ██  ██")
  );
  console.log(
    C.pink("     ██ ███ ██ ██      ██   ██ ██      ██    ██ ██   ██ ██  ██ ██")
  );
  console.log(
    C.purple("      ███ ███  ███████ ██████   ██████  ██████  ██   ██ ██   ████")
  );

  console.log();
  console.log(
    C.gray("  ┌─") +
      C.cyan(" WEBSITE INTELLIGENCE ") +
      C.gray("──────────────────────────────────────┐")
  );

  console.log(
    C.gray("  │ ") +
      C.white(`v${VERSION}`) +
      C.gray("  •  Playwright  •  Passive browser reconnaissance") +
      C.gray(" │")
  );

  console.log(
    C.gray("  └────────────────────────────────────────────────────────┘")
  );
  console.log();
}

function section(title) {
  console.log();
  console.log(C.cyan("◆ ") + C.bold(C.white(title)));
  console.log(C.gray("  " + "─".repeat(55)));
}

function success(text) {
  console.log(C.green("  ✓ ") + text);
}

function warning(text) {
  console.log(C.yellow("  ! ") + text);
}

function failure(text) {
  console.log(C.red("  ✕ ") + text);
}

function info(text) {
  console.log(C.cyan("  › ") + text);
}

function spinnerText(text) {
  process.stdout.write(
    "\r" + C.cyan("  ◈ ") + C.white(text) + " ".repeat(15)
  );
}

function clearSpinner() {
  process.stdout.write("\r" + " ".repeat(90) + "\r");
}

function ask(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) {
    input = "https://" + input;
  }

  return new URL(input);
}

function isSameOrigin(url, origin) {
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

function normalizePageUrl(url) {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.href;
  } catch {
    return null;
  }
}

function safeNumber(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

/* ============================================================
   HTTP helpers
   ============================================================ */

async function fetchText(url, timeout = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal
    });

    const text = await response.text();

    return {
      ok: true,
      status: response.status,
      url: response.url,
      headers: Object.fromEntries(response.headers.entries()),
      text
    };
  } catch (error) {
    return {
      ok: false,
      error: error.message
    };
  } finally {
    clearTimeout(timer);
  }
}

/* ============================================================
   Robots / sitemap
   ============================================================ */

async function collectRobots(origin) {
  const url = new URL("/robots.txt", origin).href;
  const result = await fetchText(url);

  if (!result.ok) {
    return {
      found: false,
      url,
      error: result.error
    };
  }

  const sitemapReferences = [];

  for (const line of result.text.split(/\r?\n/)) {
    if (/^\s*sitemap\s*:/i.test(line)) {
      sitemapReferences.push(
        line.replace(/^\s*sitemap\s*:/i, "").trim()
      );
    }
  }

  return {
    found: true,
    url,
    status: result.status,
    sitemaps: sitemapReferences,
    content: result.text
  };
}

async function collectSitemap(origin, robots) {
  const candidates = [
    ...(robots?.sitemaps || []),
    new URL("/sitemap.xml", origin).href
  ];

  const unique = [...new Set(candidates)];

  for (const url of unique) {
    const result = await fetchText(url);

    if (!result.ok) continue;

    const urls = [
      ...result.text.matchAll(
        /<loc>\s*([^<]+?)\s*<\/loc>/gi
      )
    ].map(match => match[1].trim());

    return {
      found: true,
      url,
      status: result.status,
      urls,
      raw: result.text
    };
  }

  return {
    found: false,
    urls: []
  };
}

/* ============================================================
   Header analysis
   ============================================================ */

function analyzeSecurityHeaders(headers) {
  const expected = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy"
  };

  const result = [];

  for (const [key, name] of Object.entries(expected)) {
    result.push({
      header: name,
      present: Boolean(headers[key]),
      value: headers[key] || null
    });
  }

  return result;
}

/* ============================================================
   Technology detection
   ============================================================ */

function detectTechnologies({ headers, html, scripts }) {
  const technologies = new Set();

  const text = `${JSON.stringify(headers)} ${html}`.toLowerCase();

  if (
    text.includes("__next_data__") ||
    text.includes("/_next/") ||
    text.includes("next.js")
  ) {
    technologies.add("Next.js");
  }

  if (
    text.includes("__nuxt") ||
    text.includes("/_nuxt/")
  ) {
    technologies.add("Nuxt");
  }

  if (
    text.includes("react") ||
    scripts.some(x => /react/i.test(x))
  ) {
    technologies.add("React");
  }

  if (
    text.includes("vue") ||
    scripts.some(x => /vue/i.test(x))
  ) {
    technologies.add("Vue");
  }

  if (
    text.includes("angular") ||
    scripts.some(x => /angular/i.test(x))
  ) {
    technologies.add("Angular");
  }

  if (
    text.includes("jquery") ||
    scripts.some(x => /jquery/i.test(x))
  ) {
    technologies.add("jQuery");
  }

  if (headers.server) {
    technologies.add(`Server: ${headers.server}`);
  }

  if (headers["x-powered-by"]) {
    technologies.add(`Powered by: ${headers["x-powered-by"]}`);
  }

  if (headers["cf-ray"] || headers.server?.includes("cloudflare")) {
    technologies.add("Cloudflare");
  }

  if (headers["x-vercel-id"]) {
    technologies.add("Vercel");
  }

  return [...technologies];
}

/* ============================================================
   Page DOM extraction
   ============================================================ */

async function inspectDOM(page) {
  return page.evaluate(() => {
    const absolute = value => {
      try {
        return new URL(value, location.href).href;
      } catch {
        return null;
      }
    };

    const links = [
      ...document.querySelectorAll("a[href]")
    ]
      .map(a => absolute(a.getAttribute("href")))
      .filter(Boolean);

    const scripts = [
      ...document.scripts
    ]
      .map(script => absolute(script.src))
      .filter(Boolean);

    const stylesheets = [
      ...document.querySelectorAll(
        'link[rel="stylesheet"][href]'
      )
    ]
      .map(link => absolute(link.getAttribute("href")))
      .filter(Boolean);

    const images = [
      ...document.querySelectorAll("img[src]")
    ]
      .map(img => absolute(img.getAttribute("src")))
      .filter(Boolean);

    const forms = [
      ...document.forms
    ].map(form => ({
      action: absolute(
        form.getAttribute("action") || location.href
      ),
      method: (form.method || "GET").toUpperCase(),
      enctype: form.enctype || null,

      fields: [
        ...form.elements
      ].map(field => ({
        name: field.name || null,
        type: field.type || null,
        required: Boolean(field.required)
      }))
    }));

    const meta = {};

    for (const element of document.querySelectorAll("meta")) {
      const name =
        element.getAttribute("name") ||
        element.getAttribute("property");

      const content =
        element.getAttribute("content");

      if (name && content) {
        meta[name] = content;
      }
    }

    return {
      url: location.href,
      title: document.title,

      htmlLength: document.documentElement.outerHTML.length,

      textLength:
        document.body?.innerText?.length || 0,

      language:
        document.documentElement.lang || null,

      links,
      forms,

      assets: {
        scripts,
        stylesheets,
        images
      },

      metadata: {
        meta,

        canonical:
          document.querySelector(
            'link[rel="canonical"]'
          )?.href || null,

        description:
          document.querySelector(
            'meta[name="description"]'
          )?.content || null
      }
    };
  });
}

/* ============================================================
   Full scanner
   ============================================================ */

async function scanWebsite(options) {
  const {
    target,
    maxPages = 30,
    maxDepth = 2,
    timeout = 15000,
    collectCookieValues = false
  } = options;

  const started = performance.now();

  const targetUrl = normalizeUrl(target);
  const origin = targetUrl.origin;

  const browser = await chromium.launch({
    headless: true
  });

  const context = await browser.newContext({
    viewport: {
      width: 1440,
      height: 900
    }
  });

  const pages = [];
  const endpoints = new Map();
  const assets = new Map();
  const forms = [];
  const errors = [];
  const externalDomains = new Set();
  const responses = [];

  const visited = new Set();

  const queue = [
    {
      url: targetUrl.href,
      depth: 0
    }
  ];

  let rootHeaders = {};
  let rootHTML = "";
  let rootScripts = [];

  /*
   * A browser-level request observer catches requests from
   * documents, fetch(), XHR, images, JS, CSS, etc.
   */
  context.on("request", request => {
    const url = request.url();

    try {
      const parsed = new URL(url);

      if (parsed.origin !== origin) {
        externalDomains.add(parsed.hostname);
      }
    } catch {}

    if (!endpoints.has(url)) {
      endpoints.set(url, {
        url,
        method: request.method(),
        resourceType: request.resourceType(),
        postDataPresent: Boolean(request.postData())
      });
    }
  });

  context.on("response", response => {
    const request = response.request();

    const entry = endpoints.get(request.url());

    if (entry) {
      entry.status = response.status();
      entry.responseHeaders = response.headers();
      entry.contentType =
        response.headers()["content-type"] || null;
    }

    responses.push({
      url: response.url(),
      status: response.status(),
      method: request.method(),
      resourceType: request.resourceType(),
      contentType:
        response.headers()["content-type"] || null
    });
  });

  context.on("requestfailed", request => {
    errors.push({
      url: request.url(),
      method: request.method(),
      resourceType: request.resourceType(),
      error: request.failure()?.errorText || "unknown"
    });
  });

  let firstPage = true;

  while (
    queue.length > 0 &&
    pages.length < maxPages
  ) {
    const current = queue.shift();

    if (!current) break;

    const normalized = normalizePageUrl(current.url);

    if (!normalized) continue;

    if (visited.has(normalized)) continue;

    if (!isSameOrigin(normalized, origin)) continue;

    visited.add(normalized);

    spinnerText(
      `Crawling ${pages.length + 1}/${maxPages}  ${normalized}`
    );

    const page = await context.newPage();

    try {
      const response = await page.goto(normalized, {
        waitUntil: "domcontentloaded",
        timeout
      });

      await page.waitForLoadState("networkidle", {
        timeout: Math.min(timeout, 5000)
      }).catch(() => {});

      const dom = await inspectDOM(page);

      if (firstPage) {
        rootHTML = await page.content();
        rootScripts = dom.assets.scripts;

        if (response) {
          rootHeaders = response.headers();
        }

        firstPage = false;
      }

      pages.push({
        url: dom.url,
        title: dom.title,
        depth: current.depth,
        status: response?.status() || null,
        htmlLength: dom.htmlLength,
        textLength: dom.textLength,
        language: dom.language
      });

      forms.push(
        ...dom.forms.map(form => ({
          page: dom.url,
          ...form
        }))
      );

      for (const script of dom.assets.scripts) {
        assets.set(script, {
          url: script,
          type: "script"
        });
      }

      for (const css of dom.assets.stylesheets) {
        assets.set(css, {
          url: css,
          type: "stylesheet"
        });
      }

      for (const image of dom.assets.images) {
        assets.set(image, {
          url: image,
          type: "image"
        });
      }

      if (current.depth < maxDepth) {
        for (const link of dom.links) {
          const next = normalizePageUrl(link);

          if (
            next &&
            isSameOrigin(next, origin) &&
            !visited.has(next)
          ) {
            queue.push({
              url: next,
              depth: current.depth + 1
            });
          }
        }
      }
    } catch (error) {
      errors.push({
        url: normalized,
        error: error.message
      });
    } finally {
      await page.close();
    }
  }

  clearSpinner();

  /*
   * Collect cookies.
   */
  const browserCookies = await context.cookies();

  const cookies = browserCookies.map(cookie => {
    const result = {
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      expires: cookie.expires,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite
    };

    if (collectCookieValues) {
      result.value = cookie.value;
    } else {
      result.valuePresent = Boolean(cookie.value);
    }

    return result;
  });

  /*
   * Storage from a page on the target origin.
   */
  let storage = {
    localStorageKeys: [],
    sessionStorageKeys: []
  };

  const storagePage = await context.newPage();

  try {
    await storagePage.goto(targetUrl.href, {
      waitUntil: "domcontentloaded",
      timeout
    });

    storage = await storagePage.evaluate(() => ({
      localStorageKeys:
        Object.keys(localStorage),

      sessionStorageKeys:
        Object.keys(sessionStorage)
    }));
  } catch {
    // Storage may be inaccessible depending on page behavior.
  } finally {
    await storagePage.close();
  }

  /*
   * robots.txt and sitemap.
   */
  spinnerText("Checking robots.txt...");
  const robots = await collectRobots(origin);

  spinnerText("Checking sitemap...");
  const sitemap = await collectSitemap(origin, robots);

  clearSpinner();

  /*
   * Root security header analysis.
   */
  const securityHeaders =
    analyzeSecurityHeaders(rootHeaders);

  const technologies = detectTechnologies({
    headers: rootHeaders,
    html: rootHTML,
    scripts: rootScripts
  });

  const duration =
    Math.round(performance.now() - started);

  await browser.close();

  return {
    scanner: {
      name: "webscan",
      version: VERSION,
      generatedAt: new Date().toISOString(),
      durationMs: duration
    },

    target: {
      url: targetUrl.href,
      origin,
      hostname: targetUrl.hostname,
      protocol: targetUrl.protocol
    },

    summary: {
      pages: pages.length,
      observedEndpoints: endpoints.size,
      assets: assets.size,
      forms: forms.length,
      cookies: cookies.length,
      externalDomains: externalDomains.size,
      errors: errors.length
    },

    pages,

    endpoints: [...endpoints.values()],

    responses,

    assets: [...assets.values()],

    forms,

    cookies,

    storage,

    externalDomains: [...externalDomains].sort(),

    headers: {
      all: rootHeaders,
      security: securityHeaders
    },

    technologies,

    robots,

    sitemap,

    errors
  };
}

/* ============================================================
   Report generation
   ============================================================ */

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function generateHTML(report) {
  const summary = report.summary;

  const securityRows =
    report.headers.security
      .map(item => `
        <tr>
          <td>${escapeHTML(item.header)}</td>
          <td class="${item.present ? "ok" : "bad"}">
            ${item.present ? "PRESENT" : "MISSING"}
          </td>
          <td>
            ${escapeHTML(item.value || "")}
          </td>
        </tr>
      `)
      .join("");

  const endpointRows =
    report.endpoints
      .map(endpoint => `
        <tr>
          <td>${escapeHTML(endpoint.method)}</td>
          <td>${escapeHTML(endpoint.url)}</td>
          <td>${escapeHTML(endpoint.resourceType)}</td>
          <td>${endpoint.status ?? ""}</td>
        </tr>
      `)
      .join("");

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Webscan Report</title>

<style>
body {
  margin: 0;
  background: #05070d;
  color: #dbeafe;
  font-family: Inter, system-ui, sans-serif;
}

.container {
  max-width: 1400px;
  margin: auto;
  padding: 40px;
}

h1 {
  color: #00e5ff;
}

h2 {
  margin-top: 45px;
  color: #a855f7;
}

.target {
  color: #94a3b8;
}

.grid {
  display: grid;
  grid-template-columns:
    repeat(auto-fit, minmax(160px, 1fr));
  gap: 14px;
}

.card {
  background: #0b1020;
  border: 1px solid #172554;
  border-radius: 14px;
  padding: 20px;
}

.number {
  font-size: 32px;
  color: #00e5ff;
}

table {
  width: 100%;
  border-collapse: collapse;
  background: #080c16;
}

th, td {
  text-align: left;
  padding: 12px;
  border-bottom: 1px solid #172033;
}

th {
  color: #00e5ff;
}

.ok {
  color: #22c55e;
}

.bad {
  color: #ef4444;
}

code {
  color: #c4b5fd;
}
</style>
</head>

<body>
<div class="container">

<h1>◈ WEBS CAN REPORT</h1>

<div class="target">
${escapeHTML(report.target.url)}
</div>

<h2>Overview</h2>

<div class="grid">
  <div class="card">
    <div>Pages</div>
    <div class="number">${summary.pages}</div>
  </div>

  <div class="card">
    <div>Endpoints</div>
    <div class="number">${summary.observedEndpoints}</div>
  </div>

  <div class="card">
    <div>Assets</div>
    <div class="number">${summary.assets}</div>
  </div>

  <div class="card">
    <div>Forms</div>
    <div class="number">${summary.forms}</div>
  </div>

  <div class="card">
    <div>Cookies</div>
    <div class="number">${summary.cookies}</div>
  </div>

  <div class="card">
    <div>External Domains</div>
    <div class="number">${summary.externalDomains}</div>
  </div>
</div>

<h2>Technologies</h2>

<ul>
${
  report.technologies
    .map(x => `<li>${escapeHTML(x)}</li>`)
    .join("")
}
</ul>

<h2>Security Headers</h2>

<table>
<thead>
<tr>
<th>Header</th>
<th>Status</th>
<th>Value</th>
</tr>
</thead>

<tbody>
${securityRows}
</tbody>
</table>

<h2>Observed Endpoints</h2>

<table>
<thead>
<tr>
<th>Method</th>
<th>URL</th>
<th>Type</th>
<th>Status</th>
</tr>
</thead>

<tbody>
${endpointRows}
</tbody>
</table>

<h2>External Domains</h2>

<ul>
${
  report.externalDomains
    .map(x => `<li><code>${escapeHTML(x)}</code></li>`)
    .join("")
}
</ul>

<h2>Cookies</h2>

<table>
<thead>
<tr>
<th>Name</th>
<th>Domain</th>
<th>Secure</th>
<th>HttpOnly</th>
<th>SameSite</th>
</tr>
</thead>

<tbody>
${
  report.cookies
    .map(cookie => `
      <tr>
        <td>${escapeHTML(cookie.name)}</td>
        <td>${escapeHTML(cookie.domain)}</td>
        <td>${cookie.secure}</td>
        <td>${cookie.httpOnly}</td>
        <td>${escapeHTML(cookie.sameSite)}</td>
      </tr>
    `)
    .join("")
}
</tbody>
</table>

<h2>Pages</h2>

<table>
<thead>
<tr>
<th>Status</th>
<th>Depth</th>
<th>Title</th>
<th>URL</th>
</tr>
</thead>

<tbody>
${
  report.pages
    .map(page => `
      <tr>
        <td>${page.status ?? ""}</td>
        <td>${page.depth}</td>
        <td>${escapeHTML(page.title)}</td>
        <td>${escapeHTML(page.url)}</td>
      </tr>
    `)
    .join("")
}
</tbody>
</table>

</div>
</body>
</html>`;
}

/* ============================================================
   Save reports
   ============================================================ */

async function saveReports(report) {
  const directory = path.resolve("./reports");

  await fs.mkdir(directory, {
    recursive: true
  });

  const stamp = new Date()
    .toISOString()
    .replaceAll(":", "-")
    .replaceAll(".", "-");

  const jsonPath =
    path.join(directory, `scan-${stamp}.json`);

  const htmlPath =
    path.join(directory, `scan-${stamp}.html`);

  await fs.writeFile(
    jsonPath,
    JSON.stringify(report, null, 2)
  );

  await fs.writeFile(
    htmlPath,
    generateHTML(report)
  );

  return {
    jsonPath,
    htmlPath
  };
}

/* ============================================================
   Terminal result
   ============================================================ */

function printResults(report, files) {
  clear();

  console.log(
    C.cyan("╔══════════════════════════════════════════════════════════╗")
  );

  console.log(
    C.cyan("║") +
      C.bold(C.white("              SCAN COMPLETE")) +
      C.cyan("                         ║")
  );

  console.log(
    C.cyan("╚══════════════════════════════════════════════════════════╝")
  );

  console.log();

  console.log(
    C.gray(" Target  ") +
      C.white(report.target.url)
  );

  console.log(
    C.gray(" Runtime ") +
      C.white(`${report.scanner.durationMs}ms`)
  );

  section("Discovery");

  const stats = [
    ["Pages", report.summary.pages],
    ["Observed endpoints", report.summary.observedEndpoints],
    ["Assets", report.summary.assets],
    ["Forms", report.summary.forms],
    ["Cookies", report.summary.cookies],
    ["External domains", report.summary.externalDomains],
    ["Errors", report.summary.errors]
  ];

  for (const [name, value] of stats) {
    const color =
      name === "Errors" && value > 0
        ? C.yellow
        : C.green;

    console.log(
      `  ${C.gray(name.padEnd(22))}` +
      color(String(value))
    );
  }

  section("Security Headers");

  for (const header of report.headers.security) {
    if (header.present) {
      console.log(
        C.green("  ✓ ") +
          C.white(header.header)
      );
    } else {
      console.log(
        C.yellow("  ! ") +
          C.gray(header.header)
      );
    }
  }

  section("Technologies");

  if (report.technologies.length === 0) {
    console.log(
      C.gray("  No obvious technologies detected.")
    );
  } else {
    for (const technology of report.technologies) {
      console.log(
        C.purple("  ◆ ") +
          C.white(technology)
      );
    }
  }

  section("Reports");

  console.log(
    C.cyan("  JSON  ") +
      C.white(files.jsonPath)
  );

  console.log(
    C.pink("  HTML  ") +
      C.white(files.htmlPath)
  );

  console.log();
}

/* ============================================================
   Interactive scanner
   ============================================================ */

async function runFullScan() {
  const target = await ask(
    C.cyan("  Target URL › ")
  );

  if (!target) {
    warning("No target supplied.");
    return;
  }

  let parsed;

  try {
    parsed = normalizeUrl(target);
  } catch {
    failure("Invalid URL.");
    return;
  }

  console.log();

  const maxPagesInput = await ask(
    C.gray("  Max pages [30] › ")
  );

  const maxDepthInput = await ask(
    C.gray("  Crawl depth [2] › ")
  );

  const maxPages =
    safeNumber(maxPagesInput || 30, 30);

  const maxDepth =
    safeNumber(maxDepthInput || 2, 2);

  console.log();

  warning(
    "Only scan websites you own or are authorized to assess."
  );

  info(
    "Endpoint discovery records browser-observed requests."
  );

  console.log();

  const confirmed = await ask(
    C.yellow("  Start scan? [Y/n] › ")
  );

  if (
    confirmed &&
    !["y", "yes"].includes(
      confirmed.toLowerCase()
    )
  ) {
    return;
  }

  clear();

  console.log(
    C.cyan("  ◈ INITIALIZING SCANNER")
  );

  console.log(
    C.gray(`  Target: ${parsed.href}`)
  );

  console.log();

  const report = await scanWebsite({
    target: parsed.href,
    maxPages,
    maxDepth
  });

  const files = await saveReports(report);

  printResults(report, files);
}

/* ============================================================
   Quick header scanner
   ============================================================ */

async function headerScan() {
  const target = await ask(
    C.cyan("  Target URL › ")
  );

  if (!target) return;

  let url;

  try {
    url = normalizeUrl(target);
  } catch {
    failure("Invalid URL.");
    return;
  }

  spinnerText("Fetching headers...");

  const result = await fetchText(url.href);

  clearSpinner();

  if (!result.ok) {
    failure(result.error);
    return;
  }

  clear();

  section("HTTP Headers");

  for (const [key, value] of Object.entries(
    result.headers
  )) {
    console.log(
      C.cyan(`  ${key}`) +
        C.gray(": ") +
        C.white(value)
    );
  }

  section("Security Headers");

  for (
    const header of analyzeSecurityHeaders(result.headers)
  ) {
    if (header.present) {
      success(header.header);
    } else {
      warning(header.header);
    }
  }
}

/* ============================================================
   Menu
   ============================================================ */

async function menu() {
  while (true) {
    clear();
    banner();

    console.log(
      C.white("  ") +
      C.cyan("01") +
      C.gray("  Full website scan")
    );

    console.log(
      C.white("  ") +
      C.cyan("02") +
      C.gray("  HTTP/security header scan")
    );

    console.log(
      C.white("  ") +
      C.cyan("03") +
      C.gray("  About")
    );

    console.log(
      C.white("  ") +
      C.red("00") +
      C.gray("  Exit")
    );

    console.log();
    console.log(line());

    const choice = await ask(
      C.purple("  webscan › ")
    );

    switch (choice) {
      case "1":
      case "01":
        clear();
        banner();

        try {
          await runFullScan();
        } catch (error) {
          failure(error.message);
        }

        await ask(
          C.gray("\n  Press Enter to return to menu...")
        );
        break;

      case "2":
      case "02":
        clear();
        banner();

        try {
          await headerScan();
        } catch (error) {
          failure(error.message);
        }

        await ask(
          C.gray("\n  Press Enter to return to menu...")
        );
        break;

      case "3":
      case "03":
        clear();

        banner();

        section("About");

        console.log(
          C.gray(
            "  Webscan is a browser-based website intelligence tool."
          )
        );

        console.log();
        console.log(
          C.gray(
            "  It observes information exposed during normal"
          )
        );

        console.log(
          C.gray(
            "  browser navigation and same-origin crawling."
          )
        );

        console.log();
        console.log(
          C.yellow(
            "  Use only against websites you own or are"
          )
        );

        console.log(
          C.yellow(
            "  explicitly authorized to assess."
          )
        );

        await ask(
          C.gray("\n  Press Enter to return...")
        );

        break;

      case "0":
      case "00":
      case "exit":
      case "quit":
        clear();

        console.log(
          C.cyan("\n  ◈ ") +
            C.white("Goodbye.\n")
        );

        process.exit(0);

      default:
        warning("Unknown option.");
        await sleep(700);
    }
  }
}

/* ============================================================
   Start
   ============================================================ */

process.on("SIGINT", () => {
  console.log(
    C.yellow("\n\n  Interrupted. Goodbye.\n")
  );

  process.exit(0);
});

menu().catch(error => {
  console.error(
    C.red("\nFatal error:"),
    error
  );

  process.exit(1);
});
