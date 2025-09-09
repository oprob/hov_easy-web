// Hack-o-Verse Blog — Easy Box (patched to execute <script>alert(flag)</script>)
// ---------------------------------------------------------
// Global flag for the XSS challenge (Flag 3)
var flag = "HOV{xss_popped}";

// Debug mode for Flag 2 (enable with ?debug=true)
(function debugMode() {
  var params = new URLSearchParams(window.location.search);
  if (params.get("debug") === "true") {
    console.log("%cDebug Mode: ON", "color:#66d9a3;font-weight:bold;");
    console.log("Exposing internal variable...");
    console.log("Flag 2:", "HOV{debug_console_leak}");
  }
})();

// Helper: execute any <script>...</script> contained in untrusted HTML string
function executeScriptsFrom(htmlString) {
  try {
    var tmp = document.createElement("div");
    tmp.innerHTML = htmlString;
    var scripts = tmp.querySelectorAll("script");
    scripts.forEach(function (s) {
      try {
        var code = s.textContent || s.innerText || "";
        // INTENTIONAL: Dangerous for real apps; used here to demonstrate reflected XSS
        new Function(code)();
      } catch (e) { /* swallow errors for the CTF */ }
    });
  } catch (_) {}
}

// Search feature — intentionally unsafe reflection (for Flag 3)
document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("searchForm");
  const qInput = document.getElementById("q");
  const results = document.getElementById("results");
  const resultsCard = document.getElementById("searchResults");
  const reflect = document.getElementById("reflect");

  function render(term) {
    if (!term) { resultsCard.hidden = true; return; }
    resultsCard.hidden = false;
    // Show user-controlled content directly on the page
    results.innerHTML = "Results for: " + term;
    // Also evaluate any <script> tags found in the term (to ensure <script>alert(flag)</script> works)
    executeScriptsFrom(term);
  }

  // render from URL first
  const initial = new URLSearchParams(window.location.search).get("q");
  if (initial) {
    qInput.value = initial;
    render(initial);
  }

  // handle submits
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    const term = qInput.value;
    const url = new URL(window.location.href);
    url.searchParams.set("q", term);
    history.replaceState(null, "", url.toString());
    render(term);
  });
});

// Organizer notes:
// Flag 1 (View Source): HOV{view_source_secret}
// Flag 2 (Debug console leak): add ?debug=true -> logs HOV{debug_console_leak}
// Flag 3 (Reflected XSS): payload ?q=<script>alert(flag)</script> -> pops HOV{xss_popped}
