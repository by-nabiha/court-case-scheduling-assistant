// Loaded from the same origin (allowed by the Content-Security-Policy; no inline scripts).
document.addEventListener("DOMContentLoaded", function () {
  // Confirm actions (e.g. Dispose, Complete, Delete)
  document.addEventListener("submit", function (e) {
    var msg = e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
    }
  });

  // Show/hide weight inputs depending on the chosen priority strategy
  document.addEventListener("change", function (e) {
    if (e.target.name === "strategy") {
      var w = document.getElementById("weights");
      if (w) {
        w.hidden = e.target.value !== "WEIGHTED";
      }
    }
  });

  // Demo account quick-selector (Landing page & Login)
  document.addEventListener("click", function (e) {
    var chip = e.target.closest(".demo-chip");
    if (chip) {
      var user = chip.getAttribute("data-user");
      var pass = chip.getAttribute("data-pass") || "Court@2026!";
      var uInput = document.getElementById("username");
      var pInput = document.getElementById("password");
      if (uInput && pInput) {
        uInput.value = user || "";
        pInput.value = pass;
        
        // Highlight active chip
        document.querySelectorAll(".demo-chip").forEach(function (c) {
          c.classList.remove("active");
        });
        chip.classList.add("active");

        // Subtle animation on the sign-in card
        var card = document.querySelector(".dark-signin-card") || document.querySelector(".signin-card") || document.querySelector(".login");
        if (card) {
          card.classList.add("pulse-highlight");
          setTimeout(function () {
            card.classList.remove("pulse-highlight");
          }, 600);
        }

        // Smooth scroll to form if on mobile
        var formSection = document.getElementById("signin-section");
        if (formSection && window.innerWidth < 960) {
          formSection.scrollIntoView({ behavior: "smooth" });
        }
        pInput.focus();
      }
    }

    // Quick case search box interaction
    var searchBtn = e.target.closest(".search-action-btn");
    if (searchBtn) {
      e.preventDefault();
      var sInput = document.getElementById("case-search-input");
      var q = sInput ? sInput.value.trim() : "";
      var cardTarget = document.getElementById("signin-section");
      if (cardTarget) {
        cardTarget.scrollIntoView({ behavior: "smooth", block: "center" });
        var uInp = document.getElementById("username");
        if (uInp && !uInp.value) {
          uInp.placeholder = q ? "Sign in to track " + q : "Sign in to view case";
          uInp.focus();
        }
      }
    }

    // Smooth scroll for in-page anchors
    var anchor = e.target.closest('a[href^="#"]');
    if (anchor && anchor.getAttribute("href").length > 1) {
      var targetId = anchor.getAttribute("href").substring(1);
      var targetEl = document.getElementById(targetId);
      if (targetEl) {
        e.preventDefault();
        targetEl.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
  });
});
