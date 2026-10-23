function debounce(fn, delay) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

function createBadge() {
  const badge = document.createElement("div");
  badge.style.cssText = `
    position: absolute;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-family: Arial, sans-serif;
    font-weight: bold;
    color: white;
    background: #999;
    z-index: 999999;
    pointer-events: none;
    display: none;
  `;
  document.body.appendChild(badge);
  return badge;
}

function positionBadge(badge, input) {
  const rect = input.getBoundingClientRect();
  badge.style.top = `${window.scrollY + rect.top - 32}px`;
  badge.style.left = `${window.scrollX + rect.left}px`;
}

function colorForVerdict(verdict) {
  if (verdict === "STRONG") return "#02c39a";
  if (verdict === "COMPROMISED") return "#c0392b";
  return "#e8a33d"; // any "WEAK - ..." verdict
}

async function checkPassword(password, badge) {
  try {
    const response = await fetch("http://127.0.0.1:5000/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const result = await response.json();
    badge.textContent = result.verdict;
    badge.style.background = colorForVerdict(result.verdict);
  } catch (err) {
    badge.textContent = "Checker offline";
    badge.style.background = "#777";
  }
}

const debouncedCheck = debounce((password, badge) => {
  if (password.length === 0) {
    badge.style.display = "none";
    return;
  }
  badge.style.display = "block";
  badge.textContent = "Checking...";
  badge.style.background = "#999";
  checkPassword(password, badge);
}, 500);

function attachToField(input) {
  if (input.dataset.pwCheckerAttached) return;
  input.dataset.pwCheckerAttached = "true";

  const badge = createBadge();
  positionBadge(badge, input);

  input.addEventListener("input", () => {
    positionBadge(badge, input);
    debouncedCheck(input.value, badge);
  });

  window.addEventListener("scroll", () => positionBadge(badge, input));
  window.addEventListener("resize", () => positionBadge(badge, input));
}

function scanForPasswordFields() {
  document.querySelectorAll('input[type="password"]').forEach(attachToField);
}

scanForPasswordFields();

// Watches for password fields that appear later (common on modern websites)
const observer = new MutationObserver(scanForPasswordFields);
observer.observe(document.body, { childList: true, subtree: true });