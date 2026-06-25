const dot = document.getElementById("presence-dot");
const label = document.getElementById("presence-label");

function update(online) {
    dot.dataset.status = online ? "online" : "offline";
    dot.setAttribute("aria-label", online ? "オンライン" : "オフライン");
    label.textContent = online ? "オンライン" : "オフライン";
}

update(navigator.onLine);
window.addEventListener("online", () => update(true));
window.addEventListener("offline", () => update(false));
