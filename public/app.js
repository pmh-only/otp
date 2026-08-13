"use strict";
const codes = element("#codes");
const empty = element("#empty");
const count = element("#count");
const sources = element("#sources");
const refresh = element("#refresh");
const template = element("#code-template");
refresh.addEventListener("click", () => void load(true));
void load();
setInterval(() => void load(), 15_000);
async function load(force = false) {
    refresh.disabled = true;
    try {
        const response = await fetch(force ? "/api/refresh" : "/api/otps", {
            method: force ? "POST" : "GET",
            cache: "no-store",
        });
        if (!response.ok)
            throw new Error("Unable to load codes");
        render(await response.json());
    }
    catch (error) {
        sources.textContent = error instanceof Error ? error.message : "Unable to load codes";
    }
    finally {
        refresh.disabled = false;
    }
}
function render(data) {
    count.textContent = String(data.items.length);
    empty.hidden = data.items.length !== 0;
    codes.replaceChildren(...data.items.map(renderCode));
    sources.replaceChildren(...Object.entries(data.sources).map(([name, status]) => {
        const badge = document.createElement("span");
        badge.className = status.ok ? "online" : "offline";
        badge.textContent = `${name} ${status.ok ? "live" : "unavailable"}`;
        badge.title = status.error || `Last checked ${relativeTime(status.checkedAt)}`;
        return badge;
    }));
}
function renderCode(item) {
    const card = template.content.firstElementChild?.cloneNode(true);
    if (!(card instanceof HTMLElement))
        throw new Error("Invalid code template");
    element(".source", card).textContent = item.source;
    const time = element("time", card);
    time.dateTime = item.receivedAt;
    time.textContent = relativeTime(item.receivedAt);
    element("h2", card).textContent = item.title;
    element(".sender", card).textContent = item.sender;
    const button = element(".code", card);
    button.textContent = item.code;
    button.addEventListener("click", async () => {
        await navigator.clipboard.writeText(item.code);
        card.classList.add("just-copied");
        setTimeout(() => card.classList.remove("just-copied"), 1200);
    });
    return card;
}
function relativeTime(value) {
    if (!value)
        return "never";
    const seconds = Math.round((Date.parse(value) - Date.now()) / 1000);
    const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    if (Math.abs(seconds) < 60)
        return formatter.format(seconds, "second");
    const minutes = Math.round(seconds / 60);
    if (Math.abs(minutes) < 60)
        return formatter.format(minutes, "minute");
    const hours = Math.round(minutes / 60);
    if (Math.abs(hours) < 24)
        return formatter.format(hours, "hour");
    return formatter.format(Math.round(hours / 24), "day");
}
function element(selector, root = document) {
    const value = root.querySelector(selector);
    if (!value)
        throw new Error(`Missing element: ${selector}`);
    return value;
}
