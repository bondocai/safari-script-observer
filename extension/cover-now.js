// Registered by the background script only in "check every page" mode (and not
// for trusted sites), so it runs at document start with no settings to read:
// the page is covered before it can draw anything. inspector.js then replaces
// this cover with its own (see shield in inspector.js) or removes it.
(() => {
  if (window !== window.top || !/^https?:\/\//.test(location.origin) || window.__ssoEarlyCover) return;
  const host = document.createElement("div");
  host.setAttribute("popover", "manual");
  host.style.cssText = "all:initial !important;position:fixed !important;inset:0 !important;display:block !important;" +
    "z-index:2147483646 !important;background:" +
    (matchMedia("(prefers-color-scheme: dark)").matches ? "#101828" : "#f9fafb") + " !important";
  host.attachShadow({mode: "closed"});
  const swallow = event => { event.preventDefault(); event.stopImmediatePropagation(); };
  const events = ["keydown", "keypress", "keyup", "beforeinput", "input", "paste", "drop",
                  "mousedown", "pointerdown", "click", "auxclick", "submit", "focusin"];
  for (const type of events) window.addEventListener(type, swallow, true);
  let removed = false;
  const attach = () => {
    if (removed) return;
    if (!document.documentElement) return requestAnimationFrame(attach);
    document.documentElement.append(host);
    try { host.showPopover(); } catch {}
  };
  attach();
  // Safety net if inspector.js never takes over.
  const timer = setTimeout(() => window.__ssoEarlyCover?.remove(), 45000);
  window.__ssoEarlyCover = {
    remove() {
      if (removed) return;
      removed = true;
      clearTimeout(timer);
      host.remove();
      for (const type of events) window.removeEventListener(type, swallow, true);
    }
  };
})();
