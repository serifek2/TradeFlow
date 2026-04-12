/**
 * Sayfa http://localhost:4000 dışında açıldığında (ör. Live Server :5500, file://)
 * /api/* istekleri Node sunucusuna yönlendirilir; aksi halde HTML 404 alınır.
 */
(function () {
  var host = window.location.hostname;
  var port = window.location.port;
  var base = '';
  if (window.location.protocol === 'file:') {
    base = 'http://localhost:4000';
  } else if ((host === 'localhost' || host === '127.0.0.1') && port && String(port) !== '4000') {
    base = 'http://' + host + ':4000';
  }
  if (!base) return;
  var orig = window.fetch;
  window.fetch = function (input, init) {
    if (typeof input === 'string' && input.indexOf('/api/') === 0) {
      return orig(base + input, init);
    }
    return orig(input, init);
  };
})();
