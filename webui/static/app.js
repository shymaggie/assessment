/* 复测工作台前端：纯原生 JS，无构建、无外部请求。所有动态文本走 textContent。 */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const params = new URLSearchParams(location.search);

  // ── 访问口令：来自 ?token=，存入 sessionStorage 后立刻从地址栏移除 ──
  if (params.get('token')) {
    sessionStorage.setItem('webui_token', params.get('token'));
    params.delete('token');
    history.replaceState(null, '', location.pathname + (params.toString() ? '?' + params : '') + location.hash);
  }
  const token = () => sessionStorage.getItem('webui_token') || '';

  const VCOLOR = { VULNERABLE: '#DC2626', SURFACE_PATCH: '#D97706', WAF_FULL_BLOCK: '#0891B2', PATCHED: '#059669', INCONCLUSIVE: '#94A3B8' };
  const ORDER = ['VULNERABLE', 'SURFACE_PATCH', 'WAF_FULL_BLOCK', 'PATCHED', 'INCONCLUSIVE'];
  const ROUTES = {
    dashboard: ['总览', '当前状态、趋势与变化'],
    run: ['实时复测', '进度、当前扫描节点与发现的问题'],
    checks: ['检查项', '每项检查的判定、依据与历史'],
    runs: ['运行记录', '历次复测的结果汇总'],
    evidence: ['证据', '探针原始请求与响应留存'],
    report: ['报告与完整性', '确定性摘要与代码钉扎状态'],
    roadmap: ['规划', '尚未实现的模块，仅供了解方向'],
  };

  const st = { data: null, error: null, fetchedAt: null, source: localStorage.getItem('webui_source') || 'auto',
               tv: params.get('tv') === '1', filter: 'ALL', refreshMs: 30000, timer: null };
  let labels = { verdict: {}, type: {}, kind: {} };

  // ── 基础工具 ─────────────────────────────────────────────────────────
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const k in (attrs || {})) {
      if (k === 'class') e.className = attrs[k];
      else if (k === 'text') e.textContent = attrs[k];
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== false && attrs[k] != null) e.setAttribute(k, attrs[k]);
    }
    kids.flat().forEach(c => { if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c))); });
    return e;
  }
  // replaceChildren 会把 null/false 渲染成文本 "null"，统一过滤
  const put = (host, ...kids) => host.replaceChildren(...kids.flat().filter(k => k != null && k !== false));
  const vlabel = v => labels.verdict[v] || v || '无数据';
  function vbadge(v) {
    return el('span', { class: 'vbadge' + (v === 'INCONCLUSIVE' ? ' unk' : ''), style: `--vc:${VCOLOR[v] || '#94A3B8'}` }, el('i'), vlabel(v));
  }
  const fmtTs = ts => (ts || '').replace('T', ' ').slice(0, 16);
  const fmtBytes = n => n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB';
  const fmtVal = v => typeof v === 'boolean' ? (v ? '是' : '否') : v;

  async function api(path, qs) {
    const q = new URLSearchParams(Object.assign({ source: st.source }, qs || {}));
    const res = await fetch(`${path}?${q}`, { headers: token() ? { Authorization: 'Bearer ' + token() } : {}, cache: 'no-store' });
    if (res.status === 401) throw new Error('需要访问口令：请使用带 ?token=口令 的地址打开');
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || ('请求失败 ' + res.status));
    return body;
  }
  async function post(path, payload) {
    const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'retest-webui' };
    if (token()) headers.Authorization = 'Bearer ' + token();
    const res = await fetch(path, { method: 'POST', headers, body: JSON.stringify(payload || {}), cache: 'no-store' });
    const body = await res.json().catch(() => ({}));
    if (res.status === 401) throw new Error('需要访问口令：请使用带 ?token=口令 的地址打开');
    if (!res.ok) throw new Error(body.error || ('请求失败 ' + res.status));
    return body;
  }

  // ── Tooltip（事件委托） ──────────────────────────────────────────────
  const tip = $('tip');
  document.addEventListener('mouseover', e => {
    const t = e.target.closest && e.target.closest('[data-tip]');
    if (!t) { tip.hidden = true; return; }
    tip.textContent = t.getAttribute('data-tip'); tip.hidden = false;
  });
  document.addEventListener('mousemove', e => {
    if (tip.hidden) return;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.min(e.clientX + 14, innerWidth - w - 8) + 'px';
    tip.style.top = Math.min(e.clientY + 14, innerHeight - h - 8) + 'px';
  });

  // ── 数据加载与刷新 ───────────────────────────────────────────────────
  async function load(manual) {
    try {
      st.data = await api('/api/dashboard');
      st.error = null; st.fetchedAt = new Date();
      if (st.data.labels) labels = st.data.labels;
    } catch (err) {
      st.error = err.message || String(err);
    }
    renderChrome();
    // 实时复测页有自己的轮询与局部更新，数据刷新不能把它整页重绘掉
    if (manual !== 'chrome' && (route() !== 'run' || !run.ui)) render();
  }
  function schedule() {
    clearInterval(st.timer);
    st.timer = setInterval(() => { if (!document.hidden) load(); }, st.refreshMs);
  }

  // ── 顶栏与状态 ───────────────────────────────────────────────────────
  function renderChrome() {
    const d = st.data, banner = $('banner');
    const bs = $('b-source'), bi = $('b-integrity');
    banner.hidden = true; banner.className = 'banner';
    if (st.error) {
      banner.hidden = false; banner.classList.add('err');
      banner.textContent = '数据加载失败：' + st.error + (d ? '。以下显示的是上一次成功加载的内容。' : '');
    } else if (d && d.source && (d.source.kind === 'demo' || d.source.kind === 'lab')) {
      banner.hidden = false; banner.classList.add('demo');
      const lab = d.source.kind === 'lab';
      banner.replaceChildren(
        lab ? '当前展示的是靶场演示扫描的结果：内置靶场加本地模拟网关，不代表任何真实业务的安全状态。'
            : '当前展示的是演示数据，不是你的复测结果。',
        ' ', el('a', { href: '#/run' }, lab ? '再扫描一次或扫描真实目标' : '去开始一次复测'));
    }
    if (d && d.source && d.source.kind !== 'empty') {
      const k = d.source.kind, cls = { real: 'ok', lab: 'info', demo: 'warn' }[k];
      bs.hidden = false; bs.className = 'badge ' + cls; bs.textContent = { real: '真实结果', lab: '靶场运行', demo: '演示数据' }[k];
    } else bs.hidden = true;
    if (d && d.integrity && d.integrity.status) {
      const s = d.integrity.status, cls = s === 'OK' ? 'ok' : (s === 'UNPINNED' ? 'warn' : 'bad');
      bi.hidden = false; bi.className = 'badge ' + cls;
      bi.textContent = '完整性 ' + ({ OK: '正常', DRIFT: '漂移', TAMPERED: '被篡改', UNPINNED: '未钉扎' }[s] || s);
    } else bi.hidden = true;
    const sel = $('sel-source'); if (sel.value !== st.source) sel.value = st.source;
    const parts = [];
    if (d && d.source && d.source.run_id) parts.push('运行 ' + d.source.run_id);
    if (d && d.source && d.source.generated_at) parts.push('结果生成于 ' + fmtTs(d.source.generated_at));
    if (d && d.source && d.source.target_base) parts.push('目标 ' + d.source.target_base);
    if (st.fetchedAt) parts.push('页面刷新于 ' + st.fetchedAt.toLocaleTimeString('zh-CN', { hour12: false }) + '（每 ' + st.refreshMs / 1000 + ' 秒自动刷新）');
    $('status').replaceChildren(...parts.map(p => el('span', { text: p })));
  }
  function tickClock() {
    $('clock').textContent = new Date().toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  // ── 路由 ─────────────────────────────────────────────────────────────
  const route = () => (location.hash.replace(/^#\//, '') || 'dashboard').split('?')[0];
  function render() {
    let r = route(); if (!ROUTES[r]) r = 'dashboard';
    document.querySelectorAll('.nav-list a').forEach(a => a.classList.toggle('active', a.dataset.route === r));
    $('page-title').textContent = st.tv && r === 'dashboard' ? '业务安全复测大屏' : ROUTES[r][0];
    $('page-sub').textContent = ROUTES[r][1];
    const view = $('view'); view.replaceChildren(); view._redraw = null; run.ui = null;
    if (r === 'run') { pRun(view); return; }
    if (!st.data) { view.append(el('p', { class: 'empty-note', text: st.error ? '' : '正在加载…' })); return; }
    if (st.data.empty && r !== 'roadmap') { view.append(emptyState()); return; }
    ({ dashboard: pDashboard, checks: pChecks, runs: pRuns, evidence: pEvidence, report: pReport, roadmap: pRoadmap }[r])(view);
  }
  function emptyState() {
    return el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', { text: '还没有可展示的结果' })),
      el('p', { class: 'empty-note', text: '还没有复测结果。点击下面的按钮开始一次复测：靶场演示不需要任何配置，十几秒即可完成；也可以在右上角选择「演示数据」先看看界面。' }),
      el('div', null, el('a', { class: 'btn btn-primary', href: '#/run' }, '开始复测')));
  }

  // ── 总览 ─────────────────────────────────────────────────────────────
  function kpi(label, value, sub, color, unit) {
    return el('div', { class: 'kpi', style: `--kc:${color}` }, el('div', { class: 'kpi-l', text: label }),
      el('div', { class: 'kpi-v' }, String(value), unit ? el('small', { text: unit }) : null), el('div', { class: 'kpi-s' }, sub));
  }
  function legend(items) {
    return el('div', { class: 'legend' }, items.map(i => el('span', null, el('i', { style: `background:${i.color}` }), i.label, el('b', { text: i.value != null ? i.value : '' }))));
  }
  function card(cls, title, note, ...body) {
    return el('section', { class: 'card ' + cls }, el('div', { class: 'card-h' }, el('h2', { text: title }), el('span', { text: note || '' })), ...body);
  }
  const chartOpts = () => ({ order: ORDER, stack: ['PATCHED', 'WAF_FULL_BLOCK', 'SURFACE_PATCH', 'INCONCLUSIVE', 'VULNERABLE'], colors: VCOLOR, labels: labels.verdict, typeLabel: labels.type });

  function pDashboard(view) {
    const d = st.data, k = d.kpi, dash = el('div', { class: 'dash' });
    const dl = k.risk_delta;
    const dsub = dl == null ? '首轮，暂无对比' : (dl === 0 ? '与上一轮持平' : el('span', { class: dl > 0 ? 'up' : 'down', text: (dl > 0 ? '较上轮 +' : '较上轮 ') + dl }));
    dash.append(el('div', { class: 'kpis' },
      kpi('检查项总数', k.total, `累计运行 ${k.runs} 轮`, '#4F46E5'),
      kpi('仍需处理', k.open, '漏洞仍存在 + 仅表层修补', VCOLOR.VULNERABLE),
      kpi('已关闭', k.closed, `关闭率 ${k.closed_rate}%`, VCOLOR.PATCHED),
      kpi('无法判定', k.counts.INCONCLUSIVE, '未知按有风险对待', VCOLOR.INCONCLUSIVE),
      kpi('风险指数', k.risk, dsub, '#4F46E5', '/100')));

    const trendHost = el('div', { class: 'chart' });
    dash.append(card('c-trend', '风险趋势', `最近 ${d.trend.length} 轮 · 柱：各判定数量，线：风险指数`, trendHost,
      legend([...ORDER.map(v => ({ color: VCOLOR[v], label: vlabel(v) })), { color: '#4F46E5', label: '风险指数' }])));

    const distHost = el('div', { class: 'chart' });
    dash.append(card('c-dist', '当前判定分布', '本轮结果', distHost,
      legend(d.distribution.map(x => ({ color: VCOLOR[x.verdict], label: vlabel(x.verdict), value: x.count })))));

    const mxHost = el('div', { class: 'chart' });
    dash.append(card('c-matrix', '状态矩阵', `每行一项检查，最近 ${d.matrix.runs.length} 轮`, mxHost,
      legend(ORDER.map(v => ({ color: VCOLOR[v], label: vlabel(v) })))));

    const typeHost = el('div', { class: 'chart' });
    const gHost = el('div', { class: 'chart' });
    dash.append(el('div', { class: 'c-type', style: 'display:grid;gap:1rem' },
      card('', '按漏洞类型', '各类型的当前判定', typeHost),
      card('', '整体风险', '0 = 全部已修复，100 = 全部仍存在', el('div', { class: 'gauge-wrap' }, gHost,
        el('div', { class: 'gauge-note', text: k.needs_attention ? '本轮有变化或未知项，需要关注' : '本轮无变化，处于稳态' })))));

    const al = el('ul', { class: 'list' });
    const recent = d.alerts.slice(0, 6);
    if (!recent.length) al.append(el('li', { style: 'grid-template-columns:1fr' }, el('span', { class: 'm', text: '暂无告警。回归、转入无法判定、完整性异常会出现在这里。' })));
    recent.forEach(a => al.append(el('li', null, el('span', { class: 't', text: fmtTs(a.ts) }),
      el('span', { class: 'm' }, el('b', { text: a.vuln_id }), ' ', labels.kind[a.kind] || a.kind, el('small', { text: a.title || '' })),
      el('span', null, a.from ? vbadge(a.from) : null, a.from ? el('span', { class: 'arrow', text: '→' }) : null, vbadge(a.to)))));
    dash.append(card('c-alerts', '最近告警', `累计 ${k.alerts} 条`, al));

    const chg = el('ul', { class: 'list' });
    if (!d.changes.length) chg.append(el('li', { style: 'grid-template-columns:1fr' }, el('span', { class: 'm', text: '本轮相对上一轮没有变化。' })));
    d.changes.forEach(c => chg.append(el('li', { style: 'grid-template-columns:1fr auto' },
      el('span', { class: 'm' }, el('b', { text: c.vuln_id }), ' ', labels.kind[c.kind] || c.kind, el('small', { text: c.title })),
      el('span', null, c.from ? vbadge(c.from) : null, c.from ? el('span', { class: 'arrow', text: '→' }) : null, vbadge(c.to)))));
    dash.append(card('c-side', '本轮变化', '相对上一轮', chg));
    view.append(dash);

    const o = chartOpts();
    const draw = () => {
      Charts.trend(trendHost, d.trend, o);
      Charts.donut(distHost, d.distribution.map(x => ({ label: vlabel(x.verdict), value: x.count, color: VCOLOR[x.verdict] })), { top: k.total, bottom: '项检查' });
      Charts.matrix(mxHost, d.matrix, { colors: VCOLOR, labels: labels.verdict });
      Charts.hbars(typeHost, d.by_type, o);
      Charts.gauge(gHost, k.risk, k.risk >= 66 ? VCOLOR.VULNERABLE : (k.risk >= 33 ? VCOLOR.SURFACE_PATCH : VCOLOR.PATCHED));
    };
    requestAnimationFrame(draw);
    view._redraw = draw;
  }

  // ── 检查项 ───────────────────────────────────────────────────────────
  function pChecks(view) {
    const d = st.data;
    const bar = el('div', { class: 'toolbar' });
    ['ALL', ...ORDER].forEach(v => {
      const n = v === 'ALL' ? d.checks.length : d.checks.filter(c => c.verdict === v).length;
      if (v !== 'ALL' && !n) return;
      bar.append(el('button', { class: 'chip' + (st.filter === v ? ' on' : ''), type: 'button', onclick: () => { st.filter = v; render(); } },
        (v === 'ALL' ? '全部' : vlabel(v)) + ' ' + n));
    });
    const rows = d.checks.filter(c => st.filter === 'ALL' || c.verdict === st.filter);
    const tb = el('tbody');
    rows.forEach(c => {
      const open = () => openCheck(c.vuln_id);
      tb.append(el('tr', { class: 'click', tabindex: 0, onclick: open, onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } } },
        el('td', null, el('b', { text: c.vuln_id }), el('span', { class: 'sub', text: c.title })),
        el('td', { text: labels.type[c.type] || c.type }),
        el('td', null, vbadge(c.verdict)),
        el('td', { class: 'num', text: c.streak ? `连续 ${c.streak} 轮` : '—' }),
        el('td', null, c.previous ? vbadge(c.previous) : el('span', { class: 'sub', text: '无' })),
        el('td', { class: 'mono', text: c.endpoint || '—' }),
        el('td', { class: 'num', text: c.evidence_count })));
    });
    view.append(bar, el('div', { class: 'card' }, el('div', { class: 'tbl-wrap' }, el('table', null,
      el('thead', null, el('tr', null, ['检查项', '类型', '当前判定', '持续时间', '此前判定', '检查端点', '证据数'].map(h => el('th', { text: h })))), tb)),
      rows.length ? null : el('p', { class: 'empty-note', text: '没有符合条件的检查项。' })));
  }

  async function openCheck(id) {
    const dr = $('drawer'), ov = $('overlay');
    dr.replaceChildren(el('p', { class: 'empty-note', text: '加载中…' })); dr.hidden = false; ov.hidden = false;
    try {
      const c = await api('/api/check/' + encodeURIComponent(id));
      const kv = (pairs) => el('dl', { class: 'kv' }, pairs.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', null, v)]));
      const metrics = Object.entries(c.metrics).map(([k, v]) => [k, el('span', { class: 'mono', text: String(fmtVal(v)) })]);
      const tl = el('div', { class: 'tl' }, c.timeline.map(t => el('i', { style: `background:${VCOLOR[t.verdict] || '#F1F5F9'}`, 'data-tip': `${fmtTs(t.ts)}\n${vlabel(t.verdict)}` })));
      put(dr,
        el('button', { class: 'btn x', type: 'button', onclick: closeOverlays }, '关闭'),
        el('h3', { text: c.vuln_id }), el('div', null, c.title), el('div', { style: 'margin-top:.6rem' }, vbadge(c.verdict)),
        el('h4', { text: '基本信息' }), kv([['类型', labels.type[c.type] || c.type], ['检查端点', el('span', { class: 'mono', text: c.endpoint || '—' })],
          ['规则依据', (c.rule_refs || []).join('、') || '—'], ['历史背景', c.history_note || '—'], ['预期', c.expected || '—']]),
        el('h4', { text: '判定度量（引擎产出，只读）' }), metrics.length ? kv(metrics) : el('div', { class: 'note', text: '无度量数据' }),
        el('h4', { text: `历史判定（最近 ${c.timeline.length} 轮）` }), tl,
        el('h4', { text: `证据文件（${c.evidence.length}）` }),
        c.evidence.length ? el('ul', { class: 'list' }, c.evidence.map(p => el('li', { style: 'grid-template-columns:1fr auto' },
          el('span', { class: 'mono', text: p.split('/').pop() }),
          st.data.evidence_allowed && ['real', 'lab'].includes(st.data.source.kind) ? el('button', { class: 'btn', type: 'button', onclick: () => openEvidence(p) }, '查看') : null)))
          : el('div', { class: 'note', text: '无证据文件' }),
        st.data.source.kind === 'demo' ? el('div', { class: 'note', style: 'margin-top:.8rem', text: '演示数据没有对应的证据文件。' }) : null);
    } catch (err) { dr.replaceChildren(el('button', { class: 'btn x', type: 'button', onclick: closeOverlays }, '关闭'), el('p', { class: 'empty-note', text: err.message })); }
  }
  function closeOverlays() { $('drawer').hidden = true; $('overlay').hidden = true; $('modal').hidden = true; }
  $('overlay').addEventListener('click', closeOverlays);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') { if (!$('modal').hidden) $('modal').hidden = true; else closeOverlays(); } });

  async function openEvidence(path) {
    const m = $('modal'); m.hidden = false; $('overlay').hidden = false;
    m.replaceChildren(el('div', { class: 'modal-h' }, el('b', { class: 'mono', text: path }), el('button', { class: 'btn', type: 'button', onclick: () => { m.hidden = true; } }, '关闭')), el('pre', { text: '加载中…' }));
    try {
      const r = await api('/api/evidence/file', { path });
      let body = r.text;
      try { body = JSON.stringify(JSON.parse(r.text), null, 2); } catch (e) { /* 非 JSON 原样显示 */ }
      m.replaceChildren(el('div', { class: 'modal-h' }, el('b', { class: 'mono', text: `${r.path}（${fmtBytes(r.size)}${r.truncated ? '，已截断' : ''}）` }),
        el('button', { class: 'btn', type: 'button', onclick: () => { m.hidden = true; } }, '关闭')), el('pre', { text: body }));
    } catch (err) { m.querySelector('pre').textContent = err.message; }
  }

  // ── 运行记录 ─────────────────────────────────────────────────────────
  function pRuns(view) {
    const d = st.data;
    const tb = el('tbody');
    d.runs.forEach((r, i) => tb.append(el('tr', null,
      el('td', null, el('span', { class: 'mono', text: r.run_id }), i === 0 ? el('span', { class: 'badge info', style: 'margin-left:.5rem', text: '最新' }) : null),
      el('td', { class: 'num', text: fmtTs(r.ts) }),
      el('td', null, el('div', { class: 'hb-bar', style: 'width:12rem' }, ORDER.filter(v => r.counts[v]).map(v => el('i', { style: `width:${r.counts[v] / Math.max(1, d.kpi.total, Object.values(r.counts).reduce((a, b) => a + b, 0)) * 100}%;background:${VCOLOR[v]}`, 'data-tip': `${vlabel(v)}：${r.counts[v]} 项` })))),
      el('td', { class: 'num', text: r.risk }),
      el('td', { class: 'num', text: r.changed == null ? '首轮' : r.changed }))));
    view.append(card('', '历次运行', `共 ${d.kpi.runs} 轮，列出最近 ${d.runs.length} 轮`, el('div', { class: 'tbl-wrap' }, el('table', null,
      el('thead', null, el('tr', null, ['运行 ID', '时间', '判定构成', '风险指数', '变化项数'].map(h => el('th', { text: h })))), tb))));
    const tr = Object.entries(d.transitions);
    if (tr.length) view.append(el('div', { style: 'height:1rem' }), card('', '历史变化类型统计', '统计所有相邻两轮之间的变化',
      el('ul', { class: 'list' }, tr.map(([k, n]) => el('li', { style: 'grid-template-columns:1fr auto' }, el('span', { text: labels.kind[k] || k }), el('b', { class: 'num', text: n }))))));
  }

  // ── 证据 ─────────────────────────────────────────────────────────────
  async function pEvidence(view) {
    if (st.data.source.kind === 'demo') { view.append(card('', '证据', '', el('p', { class: 'empty-note', text: '演示数据没有对应的证据文件。产生真实结果后，这里会列出每次运行的探针证据。' }))); return; }
    if (!st.data.evidence_allowed) { view.append(card('', '证据', '', el('p', { class: 'empty-note', text: '当前监听在非本机地址且未设置访问口令，为避免泄露请求与响应原文，证据不对外提供。请使用 --token 启动。' }))); return; }
    const host = el('div'); view.append(host, ); host.append(el('p', { class: 'empty-note', text: '加载中…' }));
    try {
      const r = await api('/api/evidence');
      host.replaceChildren();
      if (!r.runs.length) host.append(card('', '证据', '', el('p', { class: 'empty-note', text: '没有找到证据目录。' })));
      r.runs.forEach(run => host.append(card('', run.run_id, `${run.files.length} 个文件`, el('ul', { class: 'list' }, run.files.map(f => el('li', { style: 'grid-template-columns:1fr auto auto' },
        el('span', { class: 'mono', text: f.name }), el('span', { class: 't', text: fmtBytes(f.size) }),
        el('button', { class: 'btn', type: 'button', onclick: () => openEvidence(f.path) }, '查看')))))));
    } catch (err) { host.replaceChildren(el('p', { class: 'empty-note', text: err.message })); }
  }

  // ── 报告与完整性 ─────────────────────────────────────────────────────
  function mdRender(src) {
    const root = el('div', { class: 'md' }); const lines = src.split('\n'); let i = 0;
    const inline = (t, parent) => {
      t.split(/(`[^`]+`|\*\*[^*]+\*\*)/).forEach(p => {
        if (!p) return;
        if (p.startsWith('`')) parent.append(el('code', { text: p.slice(1, -1) }));
        else if (p.startsWith('**')) parent.append(el('b', { text: p.slice(2, -2) }));
        else parent.append(document.createTextNode(p.replace(/<br\s*\/?>/g, '\n')));
      });
      return parent;
    };
    while (i < lines.length) {
      const l = lines[i];
      let m;
      if ((m = l.match(/^(#{1,3})\s+(.*)/))) { root.append(inline(m[2], el('h' + (m[1].length + 1)))); i++; }
      else if (l.startsWith('|')) {
        const rows = []; while (i < lines.length && lines[i].startsWith('|')) rows.push(lines[i++]);
        const cells = r => r.replace(/^\||\|$/g, '').split('|').map(c => c.trim());
        const t = el('table'), h = el('tr'); cells(rows[0]).forEach(c => h.append(inline(c, el('th'))));
        t.append(el('thead', null, h)); const b = el('tbody');
        rows.slice(2).forEach(r => { const tr = el('tr'); cells(r).forEach(c => tr.append(inline(c, el('td')))); b.append(tr); });
        t.append(b); root.append(el('div', { class: 'tbl-wrap' }, t));
      } else if (l.startsWith('- ')) {
        const ul = el('ul'); while (i < lines.length && lines[i].startsWith('- ')) ul.append(inline(lines[i++].slice(2), el('li'))); root.append(ul);
      } else if (l.startsWith('>')) { root.append(el('blockquote', null, inline(l.replace(/^>\s?/, ''), el('p')))); i++; }
      else if (l.trim()) { root.append(inline(l, el('p'))); i++; } else i++;
    }
    return root;
  }
  async function pReport(view) {
    const d = st.data, ig = d.integrity;
    const igText = { OK: '代码与规则和钉扎清单一致', DRIFT: '代码或规则与钉扎清单不一致，结果需人工复核', TAMPERED: '清单摘要与外部钉扎值不符，结果不可信', UNPINNED: '尚未钉扎，无法证明代码未被改动（运行 make pin）' };
    view.append(card('', '代码完整性', '管线启动时计算 src、规则与漏洞清单的 sha256', el('dl', { class: 'kv' },
      el('dt', { text: '状态' }), el('dd', { text: (ig.status || '—') + '：' + (igText[ig.status] || '') }),
      el('dt', { text: '钉扎来源' }), el('dd', { text: ig.pinned_by || '无' }),
      el('dt', { text: '清单摘要' }), el('dd', { class: 'mono', text: ig.manifest_sha256 || '—' }),
      el('dt', { text: '变更文件' }), el('dd', { class: 'mono', text: (ig.changed_files || []).join('、') || '无' }),
      el('dt', { text: '规则版本' }), el('dd', { text: d.source.rules_version || '—' }))));
    const box = el('div'); view.append(el('div', { style: 'height:1rem' }), card('', '确定性摘要', '由 src/state.py 生成，不经过 LLM', box));
    try {
      const r = await api('/api/summary');
      if (r.markdown) box.append(mdRender(r.markdown)); else box.append(el('p', { class: 'empty-note', text: '没有 summary.md。' }));
    } catch (err) { box.append(el('p', { class: 'empty-note', text: err.message })); }
  }

  // ── 规划 ─────────────────────────────────────────────────────────────
  async function pRoadmap(view) {
    view.append(el('div', { class: 'banner stale', style: 'margin:0 0 1rem' }, '以下模块都还没有实现，只是规划，不属于当前可用的检查。详见 docs/ROADMAP.md。'));
    const host = el('div', { class: 'road' }); view.append(host);
    try {
      const r = await api('/api/roadmap');
      r.modules.forEach(m => host.append(el('div', { class: 'road-item' }, el('span', { class: 'p', text: m.phase }),
        el('div', null, el('b', { text: m.name }), el('p', { text: m.desc })), el('span', { class: 'badge mute', text: '规划中' }))));
    } catch (err) { host.append(el('p', { class: 'empty-note', text: err.message })); }
  }

  // ── 实时复测 ─────────────────────────────────────────────────────────
  const run = { snap: null, log: [], seq: 0, id: 0, prev: null, timer: null, ui: null, doneUntil: 0, watch: false };
  const fmtDur = sec => { const s = Math.max(0, Math.floor(sec || 0)); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };
  const RUN_STATUS = { idle: ['空闲', 'mute'], running: ['运行中', 'info'], done: ['已完成', 'ok'], failed: ['失败', 'bad'], cancelled: ['已取消', 'warn'] };

  async function pollRun() {
    clearTimeout(run.timer);
    let delay = 4000;
    try {
      const since = run.seq;
      const snap = await api('/api/run/status', { since });
      if (snap.id !== run.id) {
        run.id = snap.id; run.log = []; run.seq = 0; run.prev = null;
        if (since !== 0) { run.timer = setTimeout(pollRun, 0); return; }  // 新一轮：从头取日志
      }
      snap.log.forEach(e => { if (e.seq > run.seq) run.log.push(e); });
      run.seq = snap.seq; run.snap = snap;
      const finished = (run.prev === 'running' || run.watch) && !['running', 'idle'].includes(snap.status);
      run.prev = snap.status;
      if (finished) { run.watch = false; onRunFinished(snap); }
      renderRunBar();
      $('nav-dot').hidden = snap.status !== 'running';
      if (run.ui) updateRun();
      delay = snap.status === 'running' ? 700 : 4000;
    } catch (err) { /* 服务暂不可达时静默重试；数据刷新自己会显示错误横幅 */ }
    run.timer = setTimeout(pollRun, delay);
  }

  function onRunFinished(snap) {
    run.doneUntil = Date.now() + 12000;
    if (snap.status === 'done' && snap.result_source) {
      st.source = snap.result_source; localStorage.setItem('webui_source', st.source);
    }
    load();
  }

  function renderRunBar() {
    const bar = $('runbar'), s = run.snap;
    const active = !!s && s.status === 'running';
    const recent = !!s && !active && s.status !== 'idle' && Date.now() < run.doneUntil;
    if (!active && !recent) { bar.hidden = true; return; }
    bar.hidden = false; bar.className = 'runbar ' + (active ? 'on' : s.status);
    const cur = s.current;
    const text = active
      ? `复测进行中 ${Math.floor(s.progress)}%` + (cur ? `　·　${cur.vuln_id}` + (cur.step ? `　·　探针 ${cur.idx}/${cur.of}　${cur.step}` : '') : '')
      : { done: '复测完成，已切换到新结果', failed: '复测失败', cancelled: '复测已取消' }[s.status];
    const fill = el('i'); fill.style.width = s.progress + '%';
    put(bar, el('span', { class: 'runbar-t', text }), el('div', { class: 'runbar-bar' }, fill),
      st.tv ? null : el('a', { href: '#/run' }, '查看详情'));
  }

  async function startRun(mode, extra) {
    if (run.ui) run.ui.msg.hidden = true;
    try {
      await post('/api/run/start', Object.assign({ mode }, extra));
      run.watch = true; run.doneUntil = 0; pollRun();
    } catch (err) {
      if (run.ui) { run.ui.msg.textContent = err.message; run.ui.msg.hidden = false; } else alert(err.message);
    }
  }
  function startReal() {
    const t = run.snap && run.snap.caps.real.target;
    if (!confirm('将对以下目标发起真实探测，请确认你有权限测试它：\n\n' + t + '\n\n探针经 OctoBus 网关发出。继续吗？')) return;
    startRun('real', { confirm: true });
  }
  async function cancelRun() {
    try { await post('/api/run/cancel'); pollRun(); } catch (err) { alert(err.message); }
  }

  function buildLauncher(ui) {
    ui.preset = el('select', null, el('option', { value: 'default' }, '默认状态（含已知漏洞）'), el('option', { value: 'fixed' }, '全部已修复'));
    ui.labBtn = el('button', { class: 'btn btn-primary', type: 'button', onclick: () => startRun('lab', { preset: ui.preset.value }) }, '开始靶场演示扫描');
    ui.realBtn = el('button', { class: 'btn', type: 'button', onclick: startReal }, '开始真实目标扫描');
    ui.realNote = el('div', { class: 'launch-note' });
    ui.off = el('div', { class: 'banner stale', style: 'margin:0 0 1rem' });
    ui.off.hidden = true;
    const labCard = el('section', { class: 'card launch' },
      el('div', { class: 'card-h' }, el('h2', { text: '靶场演示扫描' }), el('span', { class: 'badge info', text: '无需配置' })),
      el('p', { class: 'launch-p', text: '用内置靶场（本机随机端口）和本地模拟网关，运行真实的判定引擎，约十几秒完成。结果单独存放，不会覆盖真实结果。网关是模拟的，所以结果只用于了解流程，不代表任何真实业务的安全状态。' }),
      el('label', { class: 'sel launch-sel' }, '靶场状态', ui.preset), ui.labBtn);
    const realCard = el('section', { class: 'card launch' },
      el('div', { class: 'card-h' }, el('h2', { text: '真实目标扫描' }), ui.realBadge = el('span', { class: 'badge mute', text: '检查中' })),
      el('p', { class: 'launch-p', text: '经 OctoBus 网关，对 data/vulns.json 中配置的目标逐项探测，结果写入 outputs/。只对你有授权的目标运行；点击后会再确认一次。' }),
      ui.realNote, ui.realBtn);
    return el('div', null, ui.off, el('div', { class: 'launch-grid' }, labCard, realCard));
  }

  function pRun(view) {
    const ui = run.ui = { actKey: null, logN: 0 };
    ui.badge = el('span', { class: 'badge mute' });
    ui.title = el('h2', { class: 'run-title' });
    ui.meta = el('div', { class: 'run-meta' });
    ui.actions = el('div', { class: 'run-actions' });
    ui.fill = el('i'); ui.pct = el('b', { class: 'num prog-pct' });
    ui.track = el('div', { class: 'prog' }, ui.fill);
    ui.stats = el('div', { class: 'run-stats' });
    ui.msg = el('div', { class: 'banner err', style: 'margin:0.8rem 0 0' }); ui.msg.hidden = true;
    ui.err = el('div', { class: 'banner err', style: 'margin:0.8rem 0 0' }); ui.err.hidden = true;
    const hero = el('section', { class: 'card run-hero' },
      el('div', { class: 'run-hero-top' }, el('div', null, ui.badge, ui.title, ui.meta), ui.actions),
      el('div', { class: 'prog-row' }, ui.track, ui.pct), ui.stats, ui.err);
    ui.launch = buildLauncher(ui);
    ui.curBody = el('div'); ui.findBody = el('div'); ui.nodes = el('div', { class: 'nodes' }); ui.logBody = el('div', { class: 'log' });
    const cur = card('', '当前扫描节点', '', ui.curBody); ui.curNote = cur.querySelector('.card-h span');
    const fin = card('', '发现的问题', '', ui.findBody); ui.findNote = fin.querySelector('.card-h span');
    view.append(hero, el('div', { style: 'height:1rem' }), ui.msg, ui.launch, el('div', { class: 'run-grid' }, cur, fin),
      el('div', { style: 'height:1rem' }), card('', '检查节点', '每个节点包含若干探针，圆点代表一次探针', ui.nodes),
      el('div', { style: 'height:1rem' }), card('', '实时日志', '引擎调用与判定过程', ui.logBody));
    updateRun();
  }

  function updateRun() {
    const ui = run.ui, s = run.snap;
    if (!ui) return;
    if (!s) { ui.title.textContent = '加载中…'; return; }
    const running = s.status === 'running', idle = s.status === 'idle';
    const [stLabel, stCls] = RUN_STATUS[s.status];
    ui.badge.className = 'badge ' + stCls; ui.badge.textContent = stLabel;
    ui.title.textContent = idle ? '尚未运行' : (s.labels.mode[s.mode] + (s.preset === 'fixed' ? '（靶场：全部已修复）' : ''));
    ui.meta.textContent = idle ? '在下方选择一种方式开始复测。'
      : ['运行 ' + (s.run_id || '—'), '目标 ' + (s.target || '—'), s.phase].filter(Boolean).join('　·　');
    ui.fill.style.width = s.progress + '%';
    ui.track.classList.toggle('active', running); ui.track.classList.toggle('bad', s.status === 'failed');
    ui.pct.textContent = Math.floor(s.progress) + '%';

    const done = s.vulns.filter(v => v.status === 'done').length;
    const pd = s.vulns.reduce((a, v) => a + v.probes_done, 0), pt = s.vulns.reduce((a, v) => a + v.probes_total, 0);
    ui.stats.replaceChildren(...[['已用时', fmtDur(s.elapsed)], ['检查项', `${done} / ${s.vulns.length || '—'}`],
      ['探针', `${pd} / ${pt || '—'}`], ['发现问题', String(s.findings.length)]].map(([k, v]) =>
      el('div', { class: 'stat' }, el('span', { text: k }), el('b', { class: 'num', text: v }))));

    ui.err.hidden = !(s.error && !running); ui.err.textContent = s.error || '';
    if (ui.actKey !== s.status) {
      ui.actKey = s.status;
      ui.actions.replaceChildren(...[
        running ? el('button', { class: 'btn btn-danger', type: 'button', onclick: cancelRun }, '取消复测') : null,
        s.status === 'done' ? el('a', { class: 'btn btn-primary', href: '#/dashboard' }, '查看结果总览') : null,
        s.status === 'done' ? el('a', { class: 'btn', href: '#/checks' }, '查看检查项') : null].filter(Boolean));
    }

    ui.launch.hidden = running;
    const caps = s.caps, enabled = s.enabled;
    ui.off.hidden = enabled; ui.off.textContent = enabled ? '' : '当前不能发起扫描：' + (s.disabled_reason || '');
    ui.labBtn.disabled = !enabled; ui.preset.disabled = !enabled;
    ui.realBtn.disabled = !enabled || !caps.real.ready;
    ui.realBadge.className = 'badge ' + (caps.real.ready ? 'ok' : 'warn'); ui.realBadge.textContent = caps.real.ready ? '已配置' : '未配置';
    ui.realNote.textContent = (caps.real.ready ? '目标：' + caps.real.target
      : '缺少配置：' + caps.real.missing.join('、') + '。在项目 .env 中填写后刷新本页（详见 README“从零部署”）。');

    // 当前节点
    const cur = s.current, body = ui.curBody; body.replaceChildren();
    if (running && cur) {
      ui.curNote.textContent = `第 ${cur.index}/${cur.total} 项`;
      put(body,
        el('div', { class: 'cur-id' }, el('b', { text: cur.vuln_id }), el('span', { class: 'chip-s', text: labels.type[cur.type] || cur.type })),
        el('div', { class: 'cur-title', text: cur.title }),
        el('div', { class: 'cur-step' }, el('span', { class: 'cur-lab', text: '探针' }), el('b', { class: 'num', text: cur.of ? `${cur.idx}/${cur.of}` : '—' }), el('span', { text: cur.step || '准备中' })),
        el('div', { class: 'cur-url mono', text: cur.path || '…' }),
        cur.last ? el('div', { class: 'cur-last' }, cur.last.error ? el('span', { class: 'bad-t', text: '失败：' + cur.last.error })
          : `最近响应：HTTP ${cur.last.status}　·　${cur.last.bytes || 0} B　·　${cur.last.ms} ms`) : null);
    } else {
      ui.curNote.textContent = '';
      const msg = idle ? '没有进行中的复测。'
        : s.status === 'done' ? `全部 ${s.vulns.length} 项检查已完成，用时 ${fmtDur(s.elapsed)}。`
        : s.status === 'cancelled' ? '复测已取消。' : '复测未能完成，原因见上方提示与下方日志。';
      body.append(el('p', { class: 'empty-note', text: msg }));
    }

    // 发现的问题
    ui.findNote.textContent = s.findings.length ? `${s.findings.length} 项` : '';
    ui.findBody.replaceChildren(...(s.findings.length ? s.findings.map(f => el('div', { class: 'find' },
      el('div', { class: 'find-top' }, vbadge(f.verdict), el('b', { text: f.vuln_id }), el('span', { class: 'find-t', text: fmtDur(f.t) })),
      el('div', { class: 'find-title', text: f.title }),
      el('div', { class: 'chips' }, f.metrics.map(([k, v]) => el('span', { class: 'chip-m' }, k + ' ', el('b', { text: String(fmtVal(v)) })))),
      f.rule_refs.length ? el('div', { class: 'find-rule', text: '规则依据：' + f.rule_refs.join('、') }) : null))
      : [el('p', { class: 'empty-note', text: running ? '暂未发现问题，扫描仍在进行…' : (s.status === 'done' ? '本轮没有发现问题。' : '没有数据。') })]));

    // 节点
    ui.nodes.replaceChildren(...(s.vulns.length ? s.vulns.map(v => {
      const node = el('div', { class: 'node ' + v.status }, el('div', { class: 'node-top' }, el('span', { class: 'ni ' + v.status }),
        el('b', { text: v.id.replace('VULN-', '') }), el('span', { class: 'chip-s', text: labels.type[v.type] || v.type })),
        el('div', { class: 'node-title', text: v.title }),
        el('div', { class: 'dots' }, v.steps.map(x => el('i', { class: 'dot ' + x.state, 'data-tip': x.name + '\n' + x.path }))),
        el('div', { class: 'node-foot' }, v.status === 'done' ? vbadge(v.verdict)
          : v.status === 'running' ? el('span', { class: 'run-t', text: `扫描中 ${v.probes_done}/${v.probes_total || '…'}` })
          : el('span', { class: 'wait-t', text: '等待中' })));
      if (v.verdict) node.style.setProperty('--vc', VCOLOR[v.verdict] || '#94A3B8');
      return node;
    }) : [el('p', { class: 'empty-note', text: '开始复测后，这里会列出每个检查节点。' })]));

    // 日志：增量追加，用户在底部时自动跟随
    const box = ui.logBody;
    if (run.log.length < ui.logN) { box.replaceChildren(); ui.logN = 0; }
    if (!run.log.length && !ui.logN) box.replaceChildren(el('p', { class: 'empty-note', text: '暂无日志。' }));
    if (run.log.length > ui.logN) {
      if (!ui.logN) box.replaceChildren();
      const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 48;
      for (let i = ui.logN; i < run.log.length; i++) {
        const e = run.log[i];
        box.append(el('div', { class: 'll ' + e.level }, el('span', { class: 'lt num', text: fmtDur(e.t) }), el('span', { class: 'lx', text: e.text })));
      }
      ui.logN = run.log.length;
      if (stick) box.scrollTop = box.scrollHeight;
    }
  }

  // ── 大屏模式 ─────────────────────────────────────────────────────────
  let exitTimer;
  function setTv(on) {
    st.tv = on; document.body.classList.toggle('tv', on);
    $('tv-exit').hidden = !on;
    const u = new URL(location.href); if (on) u.searchParams.set('tv', '1'); else u.searchParams.delete('tv');
    history.replaceState(null, '', u);
    if (on) {
      if (route() !== 'dashboard') location.hash = '#/dashboard';
      if (document.documentElement.requestFullscreen && !document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => {});
    } else if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    render();
  }
  document.addEventListener('mousemove', () => {
    if (!st.tv) return; document.body.classList.add('show-exit'); clearTimeout(exitTimer);
    exitTimer = setTimeout(() => document.body.classList.remove('show-exit'), 2500);
  });
  document.addEventListener('fullscreenchange', () => { if (!document.fullscreenElement && st.tv && params.get('tv') !== '1') setTv(false); });

  // ── 启动 ─────────────────────────────────────────────────────────────
  $('btn-refresh').addEventListener('click', () => load(true));
  $('btn-run').addEventListener('click', () => { location.hash = '#/run'; });
  $('btn-tv').addEventListener('click', () => setTv(true));
  $('tv-exit').addEventListener('click', () => setTv(false));
  $('sel-source').addEventListener('change', e => { st.source = e.target.value; localStorage.setItem('webui_source', st.source); load(true); });
  document.addEventListener('keydown', e => { if (e.key.toLowerCase() === 't' && !e.target.closest('select,input,textarea') && !e.metaKey && !e.ctrlKey) setTv(!st.tv); });
  window.addEventListener('hashchange', () => { closeOverlays(); render(); });
  let rt; window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => { const v = $('view'); if (v._redraw) v._redraw(); }, 120); });

  document.body.classList.toggle('tv', st.tv); $('tv-exit').hidden = !st.tv;
  tickClock(); setInterval(tickClock, 1000);
  load(); schedule(); pollRun();
})();
