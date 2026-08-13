"use strict";
const receivedCodes = element("#received-codes");
const receivedEmpty = element("#received-empty");
const receivedCount = element("#received-count");
const totpCodes = element("#totp-codes");
const totpEmpty = element("#totp-empty");
const totpCount = element("#totp-count");
const allCount = element("#all-count");
const navReceivedCount = element("#nav-received-count");
const navTotpCount = element("#nav-totp-count");
const sources = element("#sources");
const refresh = element("#refresh");
const template = element("#code-template");
const unlock = element("#unlock");
const unlockOverlay = element("#unlock-overlay");
const masterPassword = element("#master-password");
const unlockError = element("#unlock-error");
const search = element("#search");
const sourceFilter = element("#source-filter");
const receivedPane = element("#received-pane");
const totpPane = element("#totp-pane");
const sessionTime = element("#session-time");
const toast = element("#toast");
const themeToggle = element("#theme-toggle");
const browserSession = sessionStorage.getItem("otp-session") || crypto.randomUUID();
sessionStorage.setItem("otp-session", browserSession);
let snapshot = { items: [], sources: {}, refreshedAt: new Date().toISOString(), privacyLocked: false };
let activeView = "all";
let lastActivitySent = Date.now();
let sessionDeadline = Date.now() + 300_000;
let toastTimer = 0;
let theme = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
refresh.addEventListener("click", () => void load(true));
themeToggle.addEventListener("click", () => setTheme(theme === "dark" ? "light" : "dark"));
search.addEventListener("input", render);
sourceFilter.addEventListener("change", render);
unlock.addEventListener("submit", event => { event.preventDefault(); void unlockBitwarden(); });
for (const button of document.querySelectorAll(".nav-item")) {
    button.addEventListener("click", () => setView(button.dataset.view || "all"));
}
document.addEventListener("keydown", event => {
    if (event.key === "/" && document.activeElement !== search && document.activeElement !== masterPassword) {
        event.preventDefault();
        search.focus();
    }
    if (event.key === "Escape") {
        search.value = "";
        search.blur();
        render();
    }
});
for (const eventName of ["pointerdown", "keydown", "touchstart", "scroll"])
    window.addEventListener(eventName, reportActivity, { passive: true });
void load();
setTheme(theme);
setInterval(() => void load(), 15_000);
setInterval(renderSessionTimer, 1_000);
void streamEvents();
async function load(force = false) {
    refresh.disabled = true;
    try {
        const response = await apiFetch(force ? "/api/refresh" : "/api/otps", { method: force ? "POST" : "GET", cache: "no-store" });
        if (!response.ok)
            throw new Error("Unable to load codes");
        snapshot = await response.json();
        render();
    }
    catch (error) {
        sources.textContent = error instanceof Error ? error.message : "Unable to load codes";
    }
    finally {
        refresh.disabled = false;
    }
}
function render() {
    const query = search.value.trim().toLocaleLowerCase();
    const matches = (item) => !query || `${item.title} ${item.sender} ${item.code}`.toLocaleLowerCase().includes(query);
    const receivedAll = snapshot.items.filter(item => item.source !== "bitwarden");
    const totpAll = snapshot.items.filter(item => item.source === "bitwarden");
    const received = receivedAll.filter(item => (sourceFilter.value === "all" || item.source === sourceFilter.value) && matches(item));
    const totp = totpAll.filter(matches);
    receivedCount.textContent = String(received.length);
    navReceivedCount.textContent = String(receivedAll.length);
    totpCount.textContent = String(totp.length);
    navTotpCount.textContent = String(totpAll.length);
    allCount.textContent = String(snapshot.items.length);
    receivedEmpty.hidden = received.length !== 0;
    receivedCodes.replaceChildren(...received.map(renderCode));
    totpEmpty.hidden = totp.length !== 0;
    totpCodes.replaceChildren(...totp.map(renderCode));
    element("#received-empty h3").textContent = snapshot.privacyLocked ? "Workspace locked" : "No received codes";
    element("#received-empty p").textContent = snapshot.privacyLocked ? "Unlock Bitwarden to view received SMS and mail codes." : "New verification codes from SMS and mail will appear here automatically.";
    sources.replaceChildren(...Object.entries(snapshot.sources).map(([name, status]) => {
        const badge = document.createElement("span");
        badge.className = status.ok ? "online" : "offline";
        badge.textContent = `${name} ${status.ok ? "connected" : status.requiresUnlock ? "locked" : "offline"}`;
        badge.title = status.error || `Last checked ${relativeTime(status.checkedAt)}`;
        return badge;
    }));
    const requiresUnlock = snapshot.sources.bitwarden?.requiresUnlock === true;
    unlockOverlay.hidden = !requiresUnlock;
    if (requiresUnlock && document.activeElement !== masterPassword)
        queueMicrotask(() => masterPassword.focus());
}
function setView(view) {
    activeView = view;
    for (const button of document.querySelectorAll(".nav-item"))
        button.classList.toggle("active", button.dataset.view === view);
    receivedPane.hidden = view === "totp";
    totpPane.hidden = view === "received";
    document.querySelector(".boards")?.classList.toggle("single", view !== "all");
    if (activeView !== "all")
        element(activeView === "received" ? "#received-heading" : "#totp-heading").scrollIntoView({ behavior: "smooth", block: "start" });
}
async function unlockBitwarden() {
    const button = element("button[type='submit']", unlock);
    button.disabled = true;
    unlockError.textContent = "";
    try {
        const response = await apiFetch("/api/bitwarden/unlock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: masterPassword.value }) });
        masterPassword.value = "";
        if (!response.ok)
            throw new Error("Unable to unlock vault. Check your master password.");
        snapshot = await response.json();
        sessionDeadline = Date.now() + 300_000;
        render();
    }
    catch (error) {
        masterPassword.value = "";
        unlockError.textContent = error instanceof Error ? error.message : "Unable to unlock vault";
        masterPassword.focus();
    }
    finally {
        button.disabled = false;
    }
}
function renderCode(item) {
    const card = template.content.firstElementChild?.cloneNode(true);
    if (!(card instanceof HTMLElement))
        throw new Error("Invalid code template");
    element(".source", card).textContent = item.source;
    const time = element("time", card);
    time.dateTime = item.receivedAt;
    time.textContent = item.expiresAt ? countdown(item.expiresAt) : relativeTime(item.receivedAt);
    element("h3", card).textContent = item.title;
    element(".sender", card).textContent = item.sender;
    element(".code-value", card).textContent = item.code;
    const copy = async () => { await navigator.clipboard.writeText(item.code); showToast(`${item.code} copied`); };
    element(".code", card).addEventListener("click", copy);
    element(".copy-button", card).addEventListener("click", copy);
    return card;
}
function reportActivity() { const now = Date.now(); sessionDeadline = now + 300_000; if (now - lastActivitySent < 30_000)
    return; lastActivitySent = now; void apiFetch("/api/activity", { method: "POST", keepalive: true }); }
async function apiFetch(path, options = {}) { const headers = new Headers(options.headers); headers.set("X-OTP-Session", browserSession); return fetch(path, { ...options, headers }); }
async function streamEvents() { for (;;) {
    try {
        const response = await apiFetch("/api/events", { cache: "no-store" });
        if (!response.ok || !response.body)
            throw new Error("Stream unavailable");
        const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
        let buffer = "";
        for (;;) {
            const { value, done } = await reader.read();
            if (done)
                break;
            buffer += value;
            const messages = buffer.split("\n\n");
            buffer = messages.pop() || "";
            for (const message of messages) {
                const line = message.split("\n").find(value => value.startsWith("data: "));
                if (line) {
                    snapshot = JSON.parse(line.slice(6));
                    render();
                }
            }
        }
    }
    catch {
        await new Promise(resolve => setTimeout(resolve, 2_000));
    }
} }
function renderSessionTimer() { const seconds = Math.max(0, Math.ceil((sessionDeadline - Date.now()) / 1000)); sessionTime.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`; }
function showToast(message) { toast.textContent = message; toast.classList.add("visible"); clearTimeout(toastTimer); toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 1500); }
function setTheme(next) { theme = next; document.documentElement.dataset.theme = next; const label = `Switch to ${next === "dark" ? "light" : "dark"} theme`; themeToggle.title = label; themeToggle.setAttribute("aria-label", label); }
function countdown(value) { return `${Math.max(0, Math.ceil((Date.parse(value) - Date.now()) / 1000))}s`; }
function relativeTime(value) { if (!value)
    return "never"; const seconds = Math.round((Date.parse(value) - Date.now()) / 1000); const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }); if (Math.abs(seconds) < 60)
    return formatter.format(seconds, "second"); const minutes = Math.round(seconds / 60); if (Math.abs(minutes) < 60)
    return formatter.format(minutes, "minute"); const hours = Math.round(minutes / 60); if (Math.abs(hours) < 24)
    return formatter.format(hours, "hour"); return formatter.format(Math.round(hours / 24), "day"); }
function element(selector, root = document) { const value = root.querySelector(selector); if (!value)
    throw new Error(`Missing element: ${selector}`); return value; }
