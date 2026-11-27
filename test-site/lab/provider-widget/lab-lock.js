// Lab control: a known sign-in provider's widget (served in the lab check at
// https://cdn.auth0.com/lab-lock.js) draws the sign-in box.
function signIn(value, shade) {
  shade.remove();
  document.title += " signed in";
}
function draw() {
  var shade = document.createElement("div");
  shade.id = "reauth";
  shade.style.cssText = "position:fixed;inset:0;background:#0007;display:flex;align-items:center;justify-content:center";
  var box = document.createElement("div");
  box.style.cssText = "background:#fff;padding:24px;border-radius:10px;width:320px;font:15px system-ui";
  var text = document.createElement("p");
  text.textContent = "For your security, confirm your password to view pay statements.";
  var field = document.createElement("input");
  field.type = "password";
  field.id = "rp";
  var go = document.createElement("button");
  go.id = "rp-go";
  go.textContent = "Continue";
  go.onclick = function () { signIn(field.value, shade); };
  box.append(text, field, go);
  shade.appendChild(box);
  document.body.appendChild(shade);
}
window.addEventListener("load", function () { setTimeout(draw, 1000); });
