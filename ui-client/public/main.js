const BACKEND = "http://aggregator.local";

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("registerBtn");
  if (!btn) return;

  btn.addEventListener("click", () => {
    const idp = document.getElementById("idp").value.trim();
    const as = document.getElementById("as").value.trim();

    if (!idp || !as) {
      alert("Please fill in both URLs.");
      return;
    }

    const successUrl = window.location.origin + "/success.html";
    const failUrl = window.location.origin + "/fail.html";

    // Build form dynamically
    const form = document.createElement("form");
    form.method = "POST";
    form.action = BACKEND + "/registration";

    function add(name, value) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.appendChild(input);
    }

    add("openid_provider", idp);
    add("as_url", as);
    add("success_redirect", successUrl);
    add("fail_redirect", failUrl);

    document.body.appendChild(form);
    form.submit();
  });
});
