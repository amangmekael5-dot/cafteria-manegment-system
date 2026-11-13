const $ = (id) => document.getElementById(id);

// Dark / Light Theme Management
function initTheme() {
  const saved = localStorage.getItem("ddu_theme");
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const isDark = saved ? saved === "dark" : prefersDark;
  document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");
  updateThemeButtons(isDark);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "light";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("ddu_theme", next);
  updateThemeButtons(next === "dark");
}

function updateThemeButtons(isDark) {
  document.querySelectorAll(".theme-toggle-btn").forEach((b) => {
    b.innerHTML = isDark ? "☀️ Light" : "🌙 Dark";
    b.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
  });
}

// Initialize theme on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initTheme);
} else {
  initTheme();
}

function goBack() {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "/";
  }
}

// Global keyboard Backspace handler: go back when Backspace is pressed outside input fields
window.addEventListener("keydown", (e) => {
  if (e.key === "Backspace") {
    const active = document.activeElement;
    const tag = active ? active.tagName.toLowerCase() : "";
    const isEditing = tag === "input" || tag === "textarea" || (active && active.isContentEditable);
    if (!isEditing) {
      e.preventDefault();
      goBack();
    }
  }
});

async function api(url, method = "GET", body) {
  const r = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) { location = "/login.html"; return; }
  const d = await r.json().catch(() => ({}));
  if (!r.ok && !d.status) throw new Error(d.error || "Something went wrong");
  return d;
}

function row(cells) {
  const tr = document.createElement("tr");
  cells.forEach((c) => {
    const td = document.createElement("td");
    if (c instanceof Node) td.append(c); else td.textContent = c;
    tr.append(td);
  });
  return tr;
}

function btn(text, onclick, cls = "alt") {
  const b = document.createElement("button");
  b.textContent = text; b.className = cls; b.onclick = onclick;
  return b;
}

async function logout() { await api("/api/logout", "POST"); location = "/login.html"; }
