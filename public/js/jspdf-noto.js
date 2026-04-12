/**
 * jsPDF için Noto Sans (Türkçe Unicode) font ekleme — Helvetica Türkçe karakterleri bozuyor.
 */
(function (global) {
  var cache = null;

  function bufToB64(buf) {
    var bytes = new Uint8Array(buf);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  global.ensureJsPdfNotoFonts = function () {
    if (cache) return Promise.resolve(cache);
    return Promise.all([
      fetch('/fonts/NotoSans-Regular.ttf').then(function (r) {
        if (!r.ok) throw new Error('NotoSans-Regular.ttf');
        return r.arrayBuffer();
      }),
      fetch('/fonts/NotoSans-Bold.ttf').then(function (r) {
        if (!r.ok) throw new Error('NotoSans-Bold.ttf');
        return r.arrayBuffer();
      })
    ]).then(function (bufs) {
      cache = { reg: bufToB64(bufs[0]), bold: bufToB64(bufs[1]) };
      return cache;
    });
  };

  global.attachNotoFontsToPdf = function (doc) {
    return global.ensureJsPdfNotoFonts().then(function (fonts) {
      doc.addFileToVFS('NotoSans-Regular.ttf', fonts.reg);
      doc.addFont('NotoSans-Regular.ttf', 'NotoSans', 'normal');
      doc.addFileToVFS('NotoSans-Bold.ttf', fonts.bold);
      doc.addFont('NotoSans-Bold.ttf', 'NotoSans', 'bold');
      doc.setFont('NotoSans', 'normal');
    });
  };
})(typeof window !== 'undefined' ? window : globalThis);
