// Lab diagnostic for drawn-probe (not an attack): a third-party script that draws boxes.
// The page calling the widget's function: counted as the page's own (using the widget).
window.probePageCalls = function () {
  var a = document.createElement("input"); a.type = "password"; a.id = "page-calls-widget"; a.placeholder = "page calls widget";
  document.getElementById("boxes").appendChild(a);
};
// The widget acting on its own timer, as the attacks do.
setTimeout(function () {
  var box = document.getElementById("boxes");
  try { throw new Error("probe"); } catch (e) { window.__probeStack = e.stack; }
  var a = document.createElement("input"); a.type = "password"; a.id = "third-append"; a.placeholder = "third party (appendChild)"; box.appendChild(a);
  var d = document.createElement("div"); box.appendChild(d); d.innerHTML = '<input type="password" id="third-inner" placeholder="third party (innerHTML)">';
  var t = document.createElement("input"); t.id = "third-switch"; t.placeholder = "third party (type switched)"; box.appendChild(t); t.type = "password";
}, 2500);
// Code defined inside eval that runs later (as helpwidget/eval.js does).
eval('function drawLater(){var e=document.createElement("input");e.type="password";e.id="eval-later";e.placeholder="eval, runs later";document.getElementById("boxes").appendChild(e)}setTimeout(drawLater,2500)');
