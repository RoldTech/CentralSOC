// RegexSOC: minimal, functional-only JS. No decorative motion, no external libraries.
document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.querySelector("[data-sidebar-toggle]");
  const sidebar = document.querySelector(".sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => {
      const open = sidebar.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", (e) => {
      if (sidebar.classList.contains("open") && !sidebar.contains(e.target) && e.target !== toggle) {
        sidebar.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  const menuToggle = document.querySelector("[data-user-menu-toggle]");
  const menuPanel = document.querySelector("[data-user-menu-panel]");
  if (menuToggle && menuPanel) {
    menuToggle.addEventListener("click", () => {
      const open = menuPanel.hasAttribute("hidden");
      if (open) { menuPanel.removeAttribute("hidden"); } else { menuPanel.setAttribute("hidden", ""); }
      menuToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", (e) => {
      if (!menuPanel.hasAttribute("hidden") && !menuPanel.contains(e.target) && e.target !== menuToggle) {
        menuPanel.setAttribute("hidden", "");
        menuToggle.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !menuPanel.hasAttribute("hidden")) {
        menuPanel.setAttribute("hidden", "");
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.focus();
      }
    });
  }
});
