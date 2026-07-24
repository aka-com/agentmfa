// Sets the theme on <html> before first paint, so the loading placeholder
// never flashes the wrong ground. The appearance toggle beside the settings
// gear stores an explicit choice; without one the OS preference applies and
// keeps applying live. A classic pre-paint script — a module would defer
// past first paint — self-hosted like the vendor scripts for the
// 'self'-only CSP.
(function () {
  var media = window.matchMedia('(prefers-color-scheme: dark)');
  function stored() {
    try { return localStorage.getItem('theme'); } catch (e) { return null; }
  }
  function apply() {
    var choice = stored();
    document.documentElement.dataset.theme =
      choice === 'light' || choice === 'dark' ? choice : media.matches ? 'dark' : 'light';
  }
  apply();
  media.addEventListener('change', apply);
})();
