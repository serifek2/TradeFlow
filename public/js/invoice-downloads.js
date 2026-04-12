/**
 * Fatura (ücretli) ve sevk irsaliyesi (ücretsiz) PDF — finance / index ile paylaşılır.
 */
(function (global) {
  function formatInvoiceTypePdf(t) {
    if (t === 'SATIS') return 'SATIŞ';
    if (t === 'ALIS') return 'ALIŞ';
    return t || '';
  }

  function mapApiToInvoiceShape(inv, items) {
    return {
      invoiceNumber: inv.invoice_number,
      customerName: inv.customer_name,
      date: inv.date,
      type: inv.type,
      total: inv.total_amount,
      items: (items || []).map(function (it) {
        return {
          name: it.product_name || '—',
          unit_price: Number(it.unit_price),
          quantity: Number(it.quantity),
        };
      }),
    };
  }

  /**
   * Tam fatura PDF (KDV, birim fiyat, tutar).
   * @param {object} doc jsPDF instance (Noto fontları yüklü)
   * @param {object} data { invoiceNumber, customerName, date, type, total }
   * @param {Array<{name, unit_price, quantity}>} items
   */
  global.buildInvoicePdfContent = function (doc, data, items) {
    var pageWidth = doc.internal.pageSize.getWidth();
    var margin = 20;
    var maxWidth = pageWidth - margin * 2;
    var yPos = margin;

    doc.setFontSize(22);
    doc.setFont('NotoSans', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text('FATURA', margin, yPos);
    yPos += 15;

    doc.setFontSize(10);
    doc.setFont('NotoSans', 'normal');
    var customerName = data.customerName || '';
    var invoiceDate = data.date || '';
    var invoiceType = formatInvoiceTypePdf(data.type || 'SATIS');
    var formattedDate = invoiceDate;
    if (invoiceDate && String(invoiceDate).indexOf('-') >= 0) {
      var dateParts = String(invoiceDate).split('T')[0].split('-');
      if (dateParts.length === 3) {
        formattedDate = dateParts[2] + '.' + dateParts[1] + '.' + dateParts[0];
      }
    }

    doc.setFont('NotoSans', 'bold');
    doc.text('Fatura No:', margin, yPos);
    doc.setFont('NotoSans', 'normal');
    doc.text(String(data.invoiceNumber || ''), margin + 30, yPos);
    yPos += 8;

    doc.setFont('NotoSans', 'bold');
    doc.text('Müşteri:', margin, yPos);
    doc.setFont('NotoSans', 'normal');
    doc.text(customerName || '-', margin + 30, yPos);
    yPos += 8;

    doc.setFont('NotoSans', 'bold');
    doc.text('Tarih:', margin, yPos);
    doc.setFont('NotoSans', 'normal');
    doc.text(formattedDate || '-', margin + 30, yPos);
    yPos += 8;

    doc.setFont('NotoSans', 'bold');
    doc.text('Tür:', margin, yPos);
    doc.setFont('NotoSans', 'normal');
    doc.text(invoiceType, margin + 30, yPos);
    yPos += 15;

    doc.setDrawColor(200, 200, 200);
    doc.setFillColor(245, 245, 245);
    doc.rect(margin, yPos - 7, maxWidth, 10, 'FD');
    doc.setFont('NotoSans', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(0, 0, 0);
    doc.text('Ürün', margin + 3, yPos);
    doc.text('Miktar', margin + 95, yPos);
    doc.text('Birim Fiyat', margin + 125, yPos);
    doc.text('Tutar', pageWidth - margin - 3, yPos, { align: 'right' });
    yPos += 12;

    doc.setFont('NotoSans', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(0, 0, 0);

    items.forEach(function (item, index) {
      if (yPos > 260) {
        doc.addPage();
        yPos = margin + 15;
        doc.setDrawColor(200, 200, 200);
        doc.setFillColor(245, 245, 245);
        doc.rect(margin, yPos - 7, maxWidth, 10, 'FD');
        doc.setFont('NotoSans', 'bold');
        doc.setFontSize(10);
        doc.text('Ürün', margin + 3, yPos);
        doc.text('Miktar', margin + 95, yPos);
        doc.text('Birim Fiyat', margin + 125, yPos);
        doc.text('Tutar', pageWidth - margin - 3, yPos, { align: 'right' });
        yPos += 12;
        doc.setFont('NotoSans', 'normal');
        doc.setFontSize(9);
      }

      var unitPrice = Number(item.unit_price);
      var qty = Number(item.quantity);
      var lineTotal = unitPrice * qty;
      var productName = doc.splitTextToSize(item.name || '-', 85);
      var lineH = 5;
      var nameHeight = Math.max(productName.length * lineH, lineH);

      doc.setFont('NotoSans', 'normal');
      doc.text(productName, margin + 3, yPos);
      doc.text(String(qty), margin + 95, yPos);
      doc.text(unitPrice.toFixed(2) + ' TL', margin + 125, yPos);
      doc.text(lineTotal.toFixed(2) + ' TL', pageWidth - margin - 3, yPos, { align: 'right' });
      if (index < items.length - 1) {
        doc.setDrawColor(230, 230, 230);
        doc.line(margin, yPos + 3, margin + maxWidth, yPos + 3);
      }
      yPos += nameHeight + 3;
    });

    yPos += 10;
    var subtotal = Number(data.total) / 1.2;
    var vatAmount = subtotal * 0.2;
    doc.setFont('NotoSans', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(0, 0, 0);
    var valueX = pageWidth - margin;
    var labelX = valueX - 85;
    doc.text('Ara Toplam (KDV Hariç):', labelX, yPos);
    doc.text(subtotal.toFixed(2) + ' TL', valueX, yPos, { align: 'right' });
    yPos += 10;
    doc.text('KDV (%20):', labelX, yPos);
    doc.text(vatAmount.toFixed(2) + ' TL', valueX, yPos, { align: 'right' });
    yPos += 12;
    doc.setDrawColor(180, 180, 180);
    doc.setFillColor(250, 250, 250);
    doc.rect(margin, yPos, maxWidth, 12, 'FD');
    doc.setFont('NotoSans', 'bold');
    doc.setFontSize(12);
    doc.text('TOPLAM (KDV Dahil):', labelX, yPos + 8);
    doc.text(Number(data.total).toFixed(2) + ' TL', valueX, yPos + 8, { align: 'right' });

    var pageCount = doc.internal.pages.length - 1;
    doc.setFont('NotoSans', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    for (var i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.text(
        'Sayfa ' + i + ' / ' + pageCount,
        pageWidth - margin,
        doc.internal.pageSize.getHeight() - 10,
        { align: 'right' }
      );
    }
  };

  /**
   * Sevk irsaliyesi — ürün, barkod, miktar; ücret yok.
   */
  global.buildWaybillPdfContent = function (doc, inv, items) {
    var y = 18;
    doc.setFontSize(16);
    doc.setFont('NotoSans', 'bold');
    doc.text('SEVKİYAT İRSALİYESİ', 14, y);
    y += 10;
    doc.setFontSize(10);
    doc.setFont('NotoSans', 'normal');
    doc.text('Belge No: ' + String(inv.invoice_number || ''), 14, y);
    y += 6;
    var d = inv.date;
    var dateStr = '-';
    if (d) {
      var s = String(d).split('T')[0];
      var parts = s.split('-');
      if (parts.length === 3) dateStr = parts[2] + '.' + parts[1] + '.' + parts[0];
      else dateStr = s;
    }
    doc.text('Tarih: ' + dateStr, 14, y);
    y += 6;
    doc.text('Cari: ' + String(inv.customer_name || ''), 14, y);
    y += 6;
    doc.text('Tür: ' + (inv.type === 'SATIS' ? 'SATIŞ' : 'ALIŞ'), 14, y);
    y += 10;
    doc.setFont('NotoSans', 'bold');
    doc.text('Ürün', 14, y);
    doc.text('Barkod', 120, y);
    doc.text('Miktar', 175, y, { align: 'right' });
    y += 6;
    doc.setFont('NotoSans', 'normal');
    (items || []).forEach(function (it) {
      if (y > 270) {
        doc.addPage();
        y = 18;
      }
      var name = it.product_name || '';
      var lines = doc.splitTextToSize(name, 95);
      doc.text(lines, 14, y);
      doc.text(String(it.barcode || ''), 120, y);
      doc.text(String(it.quantity), 175, y, { align: 'right' });
      y += Math.max(6, lines.length * 5);
    });
    y += 10;
    doc.setFontSize(8);
    doc.setTextColor(100, 100, 100);
    doc.text('Bu sevk irsaliyesinde ücret ve fiyat bilgisi yer almaz.', 14, y);
  };

  global.downloadInvoicePdfFromApi = async function (invoiceId, authHeadersFn) {
    if (typeof window.jspdf === 'undefined' || !window.attachNotoFontsToPdf) {
      throw new Error('PDF kütüphanesi veya font yok');
    }
    var headers = typeof authHeadersFn === 'function' ? authHeadersFn() : {};
    var res = await fetch('/api/invoices/' + invoiceId, { headers: headers });
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Fatura alınamadı');
    var inv = data.invoice;
    var items = data.items || [];
    var mapped = mapApiToInvoiceShape(inv, items);
    var JsPDF = window.jspdf.jsPDF;
    var doc = new JsPDF();
    await window.attachNotoFontsToPdf(doc);
    global.buildInvoicePdfContent(doc, mapped, mapped.items);
    doc.save('fatura-' + String(inv.invoice_number || invoiceId) + '.pdf');
  };

  global.downloadWaybillPdfFromApi = async function (invoiceId, authHeadersFn) {
    if (typeof window.jspdf === 'undefined' || !window.attachNotoFontsToPdf) {
      throw new Error('PDF kütüphanesi veya font yok');
    }
    var headers = typeof authHeadersFn === 'function' ? authHeadersFn() : {};
    var res = await fetch('/api/invoices/' + invoiceId, { headers: headers });
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Fatura alınamadı');
    var inv = data.invoice;
    var items = data.items || [];
    var JsPDF = window.jspdf.jsPDF;
    var doc = new JsPDF();
    await window.attachNotoFontsToPdf(doc);
    global.buildWaybillPdfContent(doc, inv, items);
    doc.save('irsaliye-' + String(inv.invoice_number || invoiceId) + '.pdf');
  };
})(typeof window !== 'undefined' ? window : globalThis);
