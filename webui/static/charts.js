/* 图表库：纯 SVG/DOM，零依赖，可离线、可在内网大屏运行。
 * 所有文本一律用 textContent，数据中的特殊字符不会被当作标记解析。 */
(function (global) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';

  function s(tag, attrs, parent) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function txt(parent, x, y, text, attrs) {
    const e = s('text', Object.assign({ x, y }, attrs), parent);
    e.textContent = text;
    return e;
  }
  function rootFs() {
    return parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
  }
  function svgIn(host) {
    host.replaceChildren();
    const W = host.clientWidth, H = host.clientHeight;
    if (W < 20 || H < 20) return null;
    const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img' });
    host.appendChild(svg);
    return { svg, W, H };
  }
  function shortDate(ts) { return String(ts || '').slice(5, 10); }

  /* 环形图 */
  function donut(host, items, center) {
    const box = svgIn(host); if (!box) return;
    const { svg, W, H } = box, fs = rootFs();
    const total = items.reduce((a, b) => a + b.value, 0);
    const R = Math.min(W, H) / 2 - fs * 0.4, r = R * 0.68, cx = W / 2, cy = H / 2;
    if (!total) {
      s('circle', { cx, cy, r: (R + r) / 2, fill: 'none', stroke: '#E2E8F0', 'stroke-width': R - r }, svg);
    } else {
      let a0 = -Math.PI / 2;
      const nonzero = items.filter(i => i.value > 0);
      nonzero.forEach(it => {
        const frac = it.value / total;
        const a1 = a0 + frac * Math.PI * 2 - (nonzero.length > 1 ? 0.025 : 0);
        const pt = (rad, a) => [cx + rad * Math.cos(a), cy + rad * Math.sin(a)];
        let d;
        if (nonzero.length === 1) {
          d = `M ${cx} ${cy - R} A ${R} ${R} 0 1 1 ${cx - 0.01} ${cy - R} L ${cx - 0.01} ${cy - r} A ${r} ${r} 0 1 0 ${cx} ${cy - r} Z`;
        } else {
          const [x0, y0] = pt(R, a0), [x1, y1] = pt(R, a1), [x2, y2] = pt(r, a1), [x3, y3] = pt(r, a0);
          const big = a1 - a0 > Math.PI ? 1 : 0;
          d = `M ${x0} ${y0} A ${R} ${R} 0 ${big} 1 ${x1} ${y1} L ${x2} ${y2} A ${r} ${r} 0 ${big} 0 ${x3} ${y3} Z`;
        }
        const p = s('path', { d, fill: it.color }, svg);
        p.setAttribute('data-tip', `${it.label}\n${it.value} 项（${Math.round(frac * 100)}%）`);
        a0 += frac * Math.PI * 2;
      });
    }
    txt(svg, cx, cy + fs * 0.35, String(center.top), { 'text-anchor': 'middle', 'font-size': fs * 2.4, 'font-weight': 700, fill: '#0F172A', class: 'num' });
    txt(svg, cx, cy + fs * 1.9, center.bottom, { 'text-anchor': 'middle', 'font-size': fs * 0.85, fill: '#64748B' });
  }

  /* 半圆仪表：0–100 */
  function gauge(host, value, color) {
    const box = svgIn(host); if (!box) return;
    const { svg, W, H } = box, fs = rootFs();
    const R = Math.min(W / 2, H * 0.92) - fs * 0.3, cx = W / 2, cy = H * 0.94, sw = Math.max(fs * 0.7, R * 0.16);
    const arc = (a0, a1) => {
      const p = a => [cx + (R - sw / 2) * Math.cos(a), cy + (R - sw / 2) * Math.sin(a)];
      const [x0, y0] = p(a0), [x1, y1] = p(a1);
      return `M ${x0} ${y0} A ${R - sw / 2} ${R - sw / 2} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${x1} ${y1}`;
    };
    s('path', { d: arc(Math.PI, 2 * Math.PI - 0.0001), fill: 'none', stroke: '#E2E8F0', 'stroke-width': sw, 'stroke-linecap': 'round' }, svg);
    const v = Math.max(0, Math.min(100, value));
    if (v > 0) s('path', { d: arc(Math.PI, Math.PI + (v / 100) * Math.PI - 0.0001), fill: 'none', stroke: color, 'stroke-width': sw, 'stroke-linecap': 'round' }, svg);
    txt(svg, cx, cy - fs * 0.2, v.toFixed(1), { 'text-anchor': 'middle', 'font-size': fs * 2.3, 'font-weight': 700, fill: '#0F172A', class: 'num' });
  }

  /* 趋势：堆叠柱（各判定数量）+ 风险指数折线（右轴 0-100） */
  function trend(host, rows, o) {
    const box = svgIn(host); if (!box) return;
    const { svg, W, H } = box, fs = rootFs();
    const pad = { l: fs * 2.2, r: fs * 2.8, t: fs * 0.8, b: fs * 1.9 };
    const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
    const sum = r => o.order.reduce((a, k) => a + (r.counts[k] || 0), 0);
    const maxT = Math.max(1, ...rows.map(sum));
    const step = Math.max(1, Math.ceil(maxT / 4)), ymax = step * Math.ceil(maxT / step);
    const y = v => pad.t + ih - (v / ymax) * ih;
    for (let v = 0; v <= ymax; v += step) {
      s('line', { x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v), stroke: v === 0 ? '#CBD5E1' : '#EEF2F7' }, svg);
      txt(svg, pad.l - fs * 0.5, y(v) + fs * 0.3, v, { 'text-anchor': 'end', 'font-size': fs * 0.78, fill: '#64748B', class: 'num' });
    }
    [0, 50, 100].forEach(v => {
      txt(svg, W - pad.r + fs * 0.5, pad.t + ih - (v / 100) * ih + fs * 0.3, v, { 'font-size': fs * 0.78, fill: '#4F46E5', class: 'num' });
    });
    const n = rows.length, slot = iw / Math.max(n, 1), bw = Math.min(slot * 0.62, fs * 3);
    const every = Math.max(1, Math.ceil((fs * 3.6) / slot));
    const pts = [];
    rows.forEach((r, i) => {
      const cx = pad.l + slot * (i + 0.5);
      let acc = 0;
      o.stack.forEach(k => {
        const c = r.counts[k] || 0; if (!c) return;
        const top = y(acc + c), h = y(acc) - top;
        const rect = s('rect', { x: cx - bw / 2, y: top, width: bw, height: Math.max(h - 1, 0.5), fill: o.colors[k], rx: 1.5 }, svg);
        rect.setAttribute('data-tip', `${shortDate(r.ts)}　${o.labels[k]}：${c} 项`);
        acc += c;
      });
      pts.push([cx, pad.t + ih - (r.risk / 100) * ih, r]);
      if (i % every === 0 || i === n - 1) txt(svg, cx, H - fs * 0.5, shortDate(r.ts), { 'text-anchor': 'middle', 'font-size': fs * 0.78, fill: '#64748B', class: 'num' });
    });
    if (pts.length) {
      s('path', { d: pts.map((p, i) => (i ? 'L' : 'M') + p[0] + ' ' + p[1]).join(' '), fill: 'none', stroke: '#4F46E5', 'stroke-width': Math.max(2, fs * 0.15), 'stroke-linejoin': 'round' }, svg);
      pts.forEach(p => {
        const c = s('circle', { cx: p[0], cy: p[1], r: Math.max(3, fs * 0.28), fill: '#fff', stroke: '#4F46E5', 'stroke-width': 2 }, svg);
        c.setAttribute('data-tip', `${shortDate(p[2].ts)}　风险指数 ${p[2].risk}`);
      });
    }
  }

  /* 热力矩阵：行=检查项，列=运行轮次 */
  function matrix(host, m, o) {
    host.replaceChildren();
    const cols = m.runs.length;
    const grid = document.createElement('div');
    grid.className = 'mx';
    grid.style.gridTemplateColumns = `minmax(7rem, 1.1fr) repeat(${cols}, minmax(0.9rem, 1fr))`;
    const head = (t, cls) => { const d = document.createElement('div'); d.className = cls; d.textContent = t; return d; };
    grid.appendChild(head('', 'mx-corner'));
    const every = Math.max(1, Math.ceil(cols / 7));
    m.runs.forEach((r, i) => grid.appendChild(head(i % every === 0 || i === cols - 1 ? shortDate(r.ts) : '', 'mx-col num')));
    m.rows.forEach(row => {
      const lab = head('', 'mx-row');
      const id = document.createElement('b'); id.textContent = row.vuln_id.replace('VULN-', '');
      const tl = document.createElement('span'); tl.textContent = row.title;
      lab.append(id, tl); lab.title = row.title;
      grid.appendChild(lab);
      row.cells.forEach((v, i) => {
        const c = document.createElement('div');
        c.className = 'mx-cell' + (v === null ? ' mx-empty' : '') + (v === 'INCONCLUSIVE' ? ' mx-unk' : '');
        if (v) {
          c.style.backgroundColor = o.colors[v];
          c.setAttribute('data-tip', `${row.vuln_id}\n${shortDate(m.runs[i].ts)}　${o.labels[v] || v}`);
        }
        grid.appendChild(c);
      });
    });
    host.appendChild(grid);
  }

  /* 横向堆叠条：按类型 */
  function hbars(host, items, o) {
    host.replaceChildren();
    const max = Math.max(1, ...items.map(i => o.order.reduce((a, k) => a + (i.counts[k] || 0), 0)));
    items.forEach(it => {
      const row = document.createElement('div'); row.className = 'hb';
      const lab = document.createElement('span'); lab.className = 'hb-l'; lab.textContent = o.typeLabel[it.type] || it.type || '未分类';
      const bar = document.createElement('div'); bar.className = 'hb-bar';
      let total = 0;
      o.order.forEach(k => {
        const c = it.counts[k] || 0; if (!c) return; total += c;
        const seg = document.createElement('i');
        seg.style.width = (c / max * 100) + '%'; seg.style.backgroundColor = o.colors[k];
        seg.setAttribute('data-tip', `${lab.textContent}\n${o.labels[k]}：${c} 项`);
        bar.appendChild(seg);
      });
      const n = document.createElement('b'); n.className = 'num'; n.textContent = total;
      row.append(lab, bar, n); host.appendChild(row);
    });
  }

  global.Charts = { donut, gauge, trend, matrix, hbars, shortDate };
})(window);
