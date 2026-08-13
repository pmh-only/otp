interface OtpItem { id: string; code: string; source: "sms" | "mail" | "bitwarden"; sender: string; title: string; receivedAt: string; expiresAt?: string; }
interface SourceStatus { ok: boolean; checkedAt: string | null; error?: string; requiresUnlock?: boolean; }
interface Snapshot { items: OtpItem[]; sources: Record<string, SourceStatus>; refreshedAt: string; privacyLocked: boolean; }

const receivedCodes = element<HTMLElement>("#received-codes");
const receivedEmpty = element<HTMLElement>("#received-empty");
const receivedCount = element<HTMLElement>("#received-count");
const totpCodes = element<HTMLElement>("#totp-codes");
const totpEmpty = element<HTMLElement>("#totp-empty");
const totpCount = element<HTMLElement>("#totp-count");
const allCount = element<HTMLElement>("#all-count");
const navReceivedCount = element<HTMLElement>("#nav-received-count");
const navTotpCount = element<HTMLElement>("#nav-totp-count");
const sources = element<HTMLElement>("#sources");
const refresh = element<HTMLButtonElement>("#refresh");
const template = element<HTMLTemplateElement>("#code-template");
const unlock = element<HTMLFormElement>("#unlock");
const unlockOverlay = element<HTMLElement>("#unlock-overlay");
const masterPassword = element<HTMLInputElement>("#master-password");
const unlockError = element<HTMLElement>("#unlock-error");
const search = element<HTMLInputElement>("#search");
const sourceFilter = element<HTMLSelectElement>("#source-filter");
const receivedPane = element<HTMLElement>("#received-pane");
const totpPane = element<HTMLElement>("#totp-pane");
const sessionTime = element<HTMLElement>("#session-time");
const toast = element<HTMLElement>("#toast");
const themeToggle = element<HTMLButtonElement>("#theme-toggle");

let snapshot: Snapshot = { items: [], sources: {}, refreshedAt: new Date().toISOString(), privacyLocked: false };
let activeView = "all";
let lastActivitySent = Date.now();
let sessionDeadline = Date.now() + 300_000;
let toastTimer = 0;
let theme: "dark" | "light" = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";

refresh.addEventListener("click", () => void load(true));
themeToggle.addEventListener("click", () => setTheme(theme === "dark" ? "light" : "dark"));
search.addEventListener("input", render);
sourceFilter.addEventListener("change", render);
unlock.addEventListener("submit", event => { event.preventDefault(); void unlockBitwarden(); });
for (const button of document.querySelectorAll<HTMLButtonElement>(".nav-item")) {
  button.addEventListener("click", () => setView(button.dataset.view || "all"));
}
document.addEventListener("keydown", event => {
  if (event.key === "/" && document.activeElement !== search && document.activeElement !== masterPassword) { event.preventDefault(); search.focus(); }
  if (event.key === "Escape") { search.value = ""; search.blur(); render(); }
});
for (const eventName of ["pointerdown", "keydown", "touchstart", "scroll"] as const) window.addEventListener(eventName, reportActivity, { passive: true });

void load();
setTheme(theme);
setInterval(() => void load(), 15_000);
setInterval(renderSessionTimer, 1_000);
const events = new EventSource("/api/events");
events.onmessage = (event: MessageEvent<string>) => { snapshot = JSON.parse(event.data) as Snapshot; render(); };

async function load(force = false): Promise<void> {
  refresh.disabled = true;
  try {
    const response = await fetch(force ? "/api/refresh" : "/api/otps", { method: force ? "POST" : "GET", cache: "no-store" });
    if (!response.ok) throw new Error("Unable to load codes");
    snapshot = await response.json() as Snapshot;
    render();
  } catch (error) { sources.textContent = error instanceof Error ? error.message : "Unable to load codes"; }
  finally { refresh.disabled = false; }
}

function render(): void {
  const query = search.value.trim().toLocaleLowerCase();
  const matches = (item: OtpItem) => !query || `${item.title} ${item.sender} ${item.code}`.toLocaleLowerCase().includes(query);
  const receivedAll = snapshot.items.filter(item => item.source !== "bitwarden");
  const totpAll = snapshot.items.filter(item => item.source === "bitwarden");
  const received = receivedAll.filter(item => (sourceFilter.value === "all" || item.source === sourceFilter.value) && matches(item));
  const totp = totpAll.filter(matches);
  receivedCount.textContent = String(received.length); navReceivedCount.textContent = String(receivedAll.length);
  totpCount.textContent = String(totp.length); navTotpCount.textContent = String(totpAll.length); allCount.textContent = String(snapshot.items.length);
  receivedEmpty.hidden = received.length !== 0; receivedCodes.replaceChildren(...received.map(renderCode));
  totpEmpty.hidden = totp.length !== 0; totpCodes.replaceChildren(...totp.map(renderCode));
  element<HTMLElement>("#received-empty h3").textContent = snapshot.privacyLocked ? "Workspace locked" : "No received codes";
  element<HTMLElement>("#received-empty p").textContent = snapshot.privacyLocked ? "Unlock Bitwarden to view received SMS and mail codes." : "New verification codes from SMS and mail will appear here automatically.";
  sources.replaceChildren(...Object.entries(snapshot.sources).map(([name, status]) => {
    const badge = document.createElement("span"); badge.className = status.ok ? "online" : "offline";
    badge.textContent = `${name} ${status.ok ? "connected" : status.requiresUnlock ? "locked" : "offline"}`;
    badge.title = status.error || `Last checked ${relativeTime(status.checkedAt)}`; return badge;
  }));
  const requiresUnlock = snapshot.sources.bitwarden?.requiresUnlock === true;
  unlockOverlay.hidden = !requiresUnlock;
  if (requiresUnlock && document.activeElement !== masterPassword) queueMicrotask(() => masterPassword.focus());
}

function setView(view: string): void {
  activeView = view;
  for (const button of document.querySelectorAll<HTMLButtonElement>(".nav-item")) button.classList.toggle("active", button.dataset.view === view);
  receivedPane.hidden = view === "totp"; totpPane.hidden = view === "received";
  document.querySelector(".boards")?.classList.toggle("single", view !== "all");
  if (activeView !== "all") element<HTMLElement>(activeView === "received" ? "#received-heading" : "#totp-heading").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function unlockBitwarden(): Promise<void> {
  const button = element<HTMLButtonElement>("button[type='submit']", unlock); button.disabled = true; unlockError.textContent = "";
  try {
    const response = await fetch("/api/bitwarden/unlock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: masterPassword.value }) });
    masterPassword.value = "";
    if (!response.ok) throw new Error("Unable to unlock vault. Check your master password.");
    snapshot = await response.json() as Snapshot; sessionDeadline = Date.now() + 300_000; render();
  } catch (error) { masterPassword.value = ""; unlockError.textContent = error instanceof Error ? error.message : "Unable to unlock vault"; masterPassword.focus(); }
  finally { button.disabled = false; }
}

function renderCode(item: OtpItem): Element {
  const card = template.content.firstElementChild?.cloneNode(true); if (!(card instanceof HTMLElement)) throw new Error("Invalid code template");
  element<HTMLElement>(".source", card).textContent = item.source; const time = element<HTMLTimeElement>("time", card); time.dateTime = item.receivedAt; time.textContent = item.expiresAt ? countdown(item.expiresAt) : relativeTime(item.receivedAt);
  element<HTMLElement>("h3", card).textContent = item.title; element<HTMLElement>(".sender", card).textContent = item.sender; element<HTMLElement>(".code-value", card).textContent = item.code;
  const copy = async () => { await navigator.clipboard.writeText(item.code); showToast(`${item.code} copied`); };
  element<HTMLButtonElement>(".code", card).addEventListener("click", copy); element<HTMLButtonElement>(".copy-button", card).addEventListener("click", copy); return card;
}

function reportActivity(): void { const now = Date.now(); sessionDeadline = now + 300_000; if (now - lastActivitySent < 30_000) return; lastActivitySent = now; void fetch("/api/activity", { method: "POST", keepalive: true }); }
function renderSessionTimer(): void { const seconds = Math.max(0, Math.ceil((sessionDeadline - Date.now()) / 1000)); sessionTime.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`; }
function showToast(message: string): void { toast.textContent = message; toast.classList.add("visible"); clearTimeout(toastTimer); toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 1500); }
function setTheme(next: "dark" | "light"): void { theme = next; document.documentElement.dataset.theme = next; const label = `Switch to ${next === "dark" ? "light" : "dark"} theme`; themeToggle.title = label; themeToggle.setAttribute("aria-label", label); }
function countdown(value: string): string { return `${Math.max(0, Math.ceil((Date.parse(value) - Date.now()) / 1000))}s`; }
function relativeTime(value: string | null): string { if (!value) return "never"; const seconds = Math.round((Date.parse(value) - Date.now()) / 1000); const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }); if (Math.abs(seconds) < 60) return formatter.format(seconds, "second"); const minutes = Math.round(seconds / 60); if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute"); const hours = Math.round(minutes / 60); if (Math.abs(hours) < 24) return formatter.format(hours, "hour"); return formatter.format(Math.round(hours / 24), "day"); }
function element<T extends Element>(selector: string, root: ParentNode = document): T { const value = root.querySelector(selector); if (!value) throw new Error(`Missing element: ${selector}`); return value as T; }
