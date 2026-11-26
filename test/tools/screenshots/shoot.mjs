// Captures docs/screenshots/*.png from a running Sentrix (dev server + fakefleet).
//   cd test/tools/screenshots && npm install && \
//   SENTRIX_URL=http://localhost:18080 SENTRIX_USER=admin SENTRIX_PASS=… node shoot.mjs
import puppeteer from "puppeteer-core";
import { mkdirSync } from "node:fs";

const base = process.env.SENTRIX_URL || "http://localhost:18080";
const chrome = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const out = new URL("../../../docs/screenshots/", import.meta.url).pathname;
mkdirSync(out, { recursive: true });

const browser = await puppeteer.launch({ executablePath: chrome, headless: true, defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 2 } });
const page = await browser.newPage();
await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: process.env.THEME || "dark" }]);
await page.goto(base + "/login", { waitUntil: "networkidle0" });
await page.type("input[name=username]", process.env.SENTRIX_USER || "admin");
await page.type("input[name=password]", process.env.SENTRIX_PASS || "");
await Promise.all([page.waitForNavigation(), page.click("button")]);

async function shot(name, path, opts = {}) {
  // SSE pages never reach network idle: wait for load, then let charts render
  await page.goto(base + path, { waitUntil: "load" });
  await new Promise((r) => setTimeout(r, opts.wait || 800));
  await page.screenshot({ path: out + name + ".png", fullPage: !!opts.full });
  console.log("saved", name);
}
const hostId = async (name) => page.evaluate(async (n) => (await (await fetch("/api/v1/hosts")).json()).find((h) => h.hostname === n).id, name);
const plans = async () => page.evaluate(async () => (await (await fetch("/api/v1/plans")).json()));

await shot("dashboard", "/");
await shot("hosts", "/hosts");
await shot("host", "/hosts/" + (await hostId("db-01")), { wait: 1500 });
await shot("vulnerabilities", "/vulns");
await shot("cve", "/vulns/CVE-2024-6387");
await shot("host-vulns", "/hosts/" + (await hostId("web-01")) + "/vulns");
const ps = await plans();
const ready = ps.find((p) => p.status === "ready");
const done = ps.find((p) => p.status === "done");
if (ready) await shot("patch-plan", "/patches/" + ready.id, { full: false });
if (done) await shot("patch-done", "/patches/" + done.id);
await shot("alerts", "/alerts");
await shot("settings-policies", "/settings/policies");
await browser.close();
