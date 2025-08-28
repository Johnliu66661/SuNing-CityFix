// @ts-nocheck
/* ======================= 基础配置 ======================= */
const BASE_URL = ''; // 同源
const GAODE_KEY = 'b716f05eecfcae34543f6bcf7f2d8f74';

/* ======================= Token & /me ======================= */
function getToken() { return localStorage.getItem('access_token'); }
function setToken(token) { localStorage.setItem('access_token', token); }
function clearAuth() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('role');
  localStorage.removeItem('me_cache');
}
function setRole(role) { localStorage.setItem('role', role); }
function getRole() { return localStorage.getItem('role'); }
function cacheMe(me) { localStorage.setItem('me_cache', JSON.stringify(me)); }
function getCachedMe() { try { return JSON.parse(localStorage.getItem('me_cache') || 'null'); } catch { return null; } }
function setCookieSession(v){ localStorage.setItem('cookie_session', v ? '1' : '0'); }
function hasCookieSession(){ return localStorage.getItem('cookie_session') === '1'; }
function isAuthenticated(){ return !!getToken() || hasCookieSession(); }

/* ======================= 轻量加载器 ======================= */
function loadScript(src) {
  return new Promise((res, rej) => {
    if ([...document.scripts].some(s => s.src && s.src.includes(src))) return res();
    const s = document.createElement('script');
    s.src = src; s.defer = true; s.onload = res; s.onerror = rej;
    document.head.appendChild(s);
  });
}
function loadStyle(href) {
  return new Promise((res, rej) => {
    if ([...document.styleSheets].some(s => s.href && s.href.includes(href))) return res();
    const l = document.createElement('link');
    l.rel = 'stylesheet'; l.href = href; l.onload = res; l.onerror = rej;
    document.head.appendChild(l);
  });
}

/* ======================= Leaflet / Exifr（按需） ======================= */
async function ensureLeaflet() {
  if (window.L) return;
  try { await loadStyle('https://cdn.staticfile.org/leaflet/1.9.4/leaflet.css'); }
  catch { await loadStyle('/static/leaflet/leaflet.css'); }
  try { await loadScript('https://cdn.staticfile.org/leaflet/1.9.4/leaflet.js'); }
  catch { await loadScript('/static/leaflet/leaflet.js'); }
}
async function ensureExifr() {
  if (window.exifr) return;
  await loadScript('https://unpkg.com/exifr/dist/full.umd.js');
}

/* ======================= 小工具 ======================= */
const I18N = window.I18N || {};
const t = (k, d='') => (I18N[k] ?? d);
function displayMessage(el, msg, isError = false) {
  if (!el) return;
  el.textContent = msg;
  el.className = 'message';
  el.classList.add(isError ? 'error' : 'success');
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; el.textContent = ''; }, 4000);
}
function safeDate(iso) { try { return iso ? new Date(iso).toLocaleString() : '—'; } catch { return '—'; } }
function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;', '`': '&#x60;', '=': '&#x3D;' };
  return String(str ?? '').replace(/[&<>"'`=\/]/g, (s) => map[s]);
}
function hideAllSections(){
  document.getElementById('home-section')?.classList.add('hidden');
  document.getElementById('login-section')?.classList.add('hidden');
  document.getElementById('main-app-section')?.classList.add('hidden');
}
function showSectionById(id){
  hideAllSections();
  document.getElementById(id)?.classList.remove('hidden');
  window.scrollTo({top:0, behavior:'smooth'});
}

/* ======================= 统一 fetch 封装 ======================= */
async function apiFetch(path, { method='GET', headers={}, body, baseURL = BASE_URL || '', token } = {}) {
  const authToken = token || getToken();
  const finalHeaders = { 'Accept':'application/json', ...headers };
  if (authToken) finalHeaders['Authorization'] = `Bearer ${authToken}`;

  const resp = await fetch(`${baseURL}${path}`, {
    method,
    headers: finalHeaders,
    body,
    credentials: 'include'
  });

  if (resp.status === 401) {
    clearAuth(); setCookieSession(false);
    updateNavAndHeroForAuth(); navTo('login');
    const userLoginMessage = document.getElementById('user-login-message');
    displayMessage(userLoginMessage, '登录已过期，请重新登录', true);
    throw new Error('Unauthorized');
  }
  return resp;
}

/* ======================= 角色工具 ======================= */
function normalizeRole(input) {
  const raw = String(input || '').trim().toLowerCase();
  const map = new Map([
    ['维护员','maintainer'],['維護員','maintainer'],['维修员','maintainer'],['維修員','maintainer'],
    ['运维','maintainer'],  ['運維','maintainer'],  ['维保','maintainer'],  ['維保','maintainer'],
    ['维修','maintainer'],  ['維修','maintainer'],  ['maintainer','maintainer'],
    ['用户','user'],['普通用户','user'],['user','user'],
  ]);
  return map.get(raw) || raw;
}
async function setUserRoleAligned({ identifier, role, baseURL = '', token } = {}) {
  const idOrName = String(identifier ?? '').trim();
  if (!idOrName) throw new Error('请提供用户名或用户ID');
  const normalized = normalizeRole(role);
  const allowed = ['user', 'maintainer'];
  if (!allowed.includes(normalized)) throw new Error(`无效的角色 "${role}"。允许：${allowed.join(', ')}`);

  const isNumericId = /^\d+$/.test(idOrName);
  if (!isNumericId) {
    const resp = await apiFetch('/admin/users/role', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: idOrName, role: normalized }), baseURL, token,
    });
    const data = await resp.json().catch(()=>({}));
    if (resp.ok) return data;
    if (resp.status === 404 || resp.status === 405) throw new Error('后端未提供 /admin/users/role 接口，请改用用户ID或启用该接口。');
    throw new Error(data.msg || `设置角色失败（${resp.status}）`);
  }
  const resp2 = await apiFetch(`/admin/users/${idOrName}/role`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: normalized }), baseURL, token,
  });
  const data2 = await resp2.json().catch(()=>({}));
  if (resp2.ok) return data2;
  throw new Error(data2.msg || `设置角色失败（${resp2.status}）`);
}
async function setUserRole(usernameOrId, role) { return setUserRoleAligned({ identifier: usernameOrId, role }); }

/* ======================= 顶部导航/主页 CTA ======================= */
function updateNavAndHeroForAuth() {
  const authed = isAuthenticated();
  const me = getCachedMe();

  const linkApp = document.getElementById('link-app');
  const linkLogin = document.getElementById('link-login');
  const ctaGuest = document.getElementById('cta-guest');
  const ctaAuthed = document.getElementById('cta-authed');
  const badgeLogged = document.getElementById('badge-logged');

  if (linkApp)   linkApp.classList.toggle('hidden', !authed);
  if (linkLogin) linkLogin.classList.toggle('hidden', authed);
  if (ctaGuest)  ctaGuest.classList.toggle('hidden', authed);
  if (ctaAuthed) ctaAuthed.classList.toggle('hidden', !authed);

  if (badgeLogged) {
    const name = me?.username || '';
    badgeLogged.textContent = name ? (t('signed_in_as','已登录：') + name) : t('signed_in_as','已登录');
  }
}

/* ======================= 登录卡片切换 ======================= */
function showLogin(which){
  const map = {
    'login':'user-login-section', 'user':'user-login-section',
    'maint':'maintainer-login-section',
    'admin':'admin-login-section',
    'register':'user-register-section'
  };
  const targetId = map[which] || 'user-login-section';
  ['user-login-section','maintainer-login-section','admin-login-section','user-register-section']
    .forEach(id => document.getElementById(id)?.classList.add('hidden'));
  document.getElementById(targetId)?.classList.remove('hidden');

  const hashMap = { 'user':'#login', 'login':'#login', 'maint':'#maint', 'admin':'#admin', 'register':'#register' };
  const h = hashMap[which] || '#login';
  if (location.hash !== h) location.hash = h;
}

/* ======================= 路由 ======================= */
function navTo(where){
  const target = (where || 'home').toLowerCase();

  if (target === 'home'){
    showSectionById('home-section');
    location.hash = '#home';
    triggerReveal();
    return;
  }

  if (target === 'login' || target === 'user'){
    showSectionById('login-section');
    showLogin('user');
    location.hash = '#login';
    triggerReveal();
    return;
  }

  if (target === 'admin' || target === 'maint' || target === 'register'){
    showSectionById('login-section');
    showLogin(target);
    location.hash = '#' + target;
    triggerReveal();
    return;
  }

  if (target === 'app'){
    (async ()=>{
      if (isAuthenticated()){
        showSectionById('main-app-section');
        await forceMapOn();        // <<< 确保先加载 Leaflet
        updateWhoAmI();
        await fetchReports();
        location.hash = '#app';
      }else{
        showSectionById('login-section'); showLogin('user'); location.hash = '#login';
      }
      triggerReveal();
    })();
    return;
  }
}
function routeFromHash(){
  const h = (location.hash || '#home').toLowerCase();
  if (h.startsWith('#app')) return navTo('app');
  if (h === '#admin' || h === '#maint' || h === '#register'){
    showSectionById('login-section'); showLogin(h.substring(1)); triggerReveal(); return;
  }
  if (h.startsWith('#login')) { showSectionById('login-section'); showLogin('user'); triggerReveal(); return; }
  return navTo('home');
}

/* ======================= /me & 身份显示 ======================= */
async function fetchMe() {
  if (!isAuthenticated()) return null;
  try {
    const resp = await apiFetch('/me', { method: 'GET' });
    const meInfo = await resp.json();
    if (resp.ok) {
      cacheMe(meInfo);
      if (meInfo.role) setRole(meInfo.role);
      return meInfo;
    }
  } catch {}
  return null;
}
function updateWhoAmI() {
  const meInfo = getCachedMe();
  const whoamiText = document.getElementById('whoami-text');
  const filterSortControls = document.getElementById('filter-sort-controls');
  const maintainerTools = document.getElementById('maintainer-tools');
  const assignedOnlyCheckbox = document.getElementById('assigned-only');
  const adminTools = document.getElementById('admin-tools');

  const currentRole = meInfo?.role || getRole();
  const roleText = currentRole === 'admin'
    ? (t('role_admin','管理员'))
    : currentRole === 'maintainer'
      ? (t('role_maintainer','维护员'))
      : currentRole ? t('role_user','用户') : t('no_login','未登录');

  if (whoamiText) whoamiText.textContent = (t('current_role_label','当前身份：')) + roleText;

  if (filterSortControls) filterSortControls.style.display = (currentRole === 'user') ? 'none' : 'grid';
  if (maintainerTools) {
    const show = currentRole === 'maintainer';
    maintainerTools.style.display = show ? 'block' : 'none';
    if (!show && assignedOnlyCheckbox) assignedOnlyCheckbox.checked = false;
  }
  if (adminTools) adminTools.style.display = (currentRole === 'admin') ? 'block' : 'none';
}

/* ======================= 登录/注册（多后端兼容） ======================= */
function findToken(obj){
  if (!obj || typeof obj !== 'object') return null;
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (/(^|_)access_token$|(^|_)token$|(^|_)jwt$/i.test(k) && typeof v === 'string' && v.length > 10) return v;
    if (v && typeof v === 'object') { const t = findToken(v); if (t) return t; }
  }
  return null;
}
const API_PREFIXES = ['', '/api', '/v1'];
async function smartPost(pathCandidates, payload) {
  const errors = [];
  for (const prefix of API_PREFIXES) {
    for (const path of pathCandidates) {
      const url = `${BASE_URL || ''}${prefix}${path}`;
      // JSON
      try {
        let res = await fetch(url, {
          method:'POST',
          headers:{ 'Content-Type':'application/json', 'Accept':'application/json' },
          body: JSON.stringify(payload),
          credentials:'include'
        });
        const data = await res.json().catch(()=> ({}));
        if (res.ok) return { res, data, url };
        if ([404,405,415].includes(res.status)) throw new Error(`(${res.status})`);
        errors.push(`POST JSON ${url} -> ${res.status} ${data.msg||''}`);
      } catch {}
      // FORM
      try {
        let res = await fetch(url, {
          method:'POST',
          headers:{ 'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json' },
          body: new URLSearchParams(payload).toString(),
          credentials:'include'
        });
        const data = await res.json().catch(()=> ({}));
        if (res.ok) return { res, data, url };
        if ([404,405,415].includes(res.status)) throw new Error(`(${res.status})`);
        errors.push(`POST FORM ${url} -> ${res.status} ${data.msg||''}`);
      } catch {}
    }
  }
  throw new Error('所有候选接口均未通过：\n' + errors.slice(0,6).join('\n'));
}
async function userLogin(username, password) {
  const msgEl = document.getElementById('user-login-message');
  try {
    const { data } = await smartPost(['/user/login','/login','/auth/login'], { username, password });
    const tk = findToken(data);
    if (tk) setToken(tk); else setCookieSession(true);
    const me = await fetchMe();
    if (!me) throw new Error('登录成功但 /me 不可用（可能是跨域 Cookie 被浏览器拦截）');
    displayMessage(msgEl, '登录成功！');
    navTo('app');
  } catch (e) {
    clearAuth(); setCookieSession(false);
    displayMessage(msgEl, e.message || '登录失败', true);
  }
}
async function maintLogin(username, password) {
  const msgEl = document.getElementById('maint-login-message');
  try {
    const { data } = await smartPost(['/user/login','/login','/auth/login'], { username, password });
    const tk = findToken(data);
    if (tk) setToken(tk); else setCookieSession(true);
    const me = await fetchMe();
    if (me?.role !== 'maintainer') { clearAuth(); setCookieSession(false); throw new Error('该账号不是维护员，请联系管理员设置角色为 maintainer'); }
    displayMessage(msgEl, '维护员登录成功！');
    navTo('app');
  } catch (e) {
    displayMessage(msgEl, e.message || '登录失败', true);
  }
}
async function loginAdmin(username, password) {
  const msgEl = document.getElementById('admin-login-message');
  try {
    const { data } = await smartPost(['/admin/login','/login','/auth/admin/login'], { username, password });
    const tk = findToken(data);
    if (tk) setToken(tk); else setCookieSession(true);
    const me = await fetchMe();
    if (me?.role !== 'admin') { clearAuth(); setCookieSession(false); throw new Error('不是管理员账号'); }
    displayMessage(msgEl, '管理员登录成功！');
    navTo('app');
  } catch (e) {
    displayMessage(msgEl, e.message || '登录失败', true);
  }
}
async function userRegister(username, password, email) {
  const msgEl = document.getElementById('register-message');
  try {
    const { data } = await smartPost(['/user/register','/register','/auth/register'], { username, password, email });
    displayMessage(msgEl, data?.msg || '注册成功，请登录');
    showLogin('user');
  } catch (e) {
    displayMessage(msgEl, e.message || '注册失败', true);
  }
}

/* ======================= 列表 / 筛选 / 分页 ======================= */
let currentPage = 1;
const reportsPerPage = 6;
let lastReportsPage = [];
let lastPagination = null;

function normalizeReports(arr) {
  return arr.map((r, idx) => ({
    id: r.id ?? idx,
    report_type: r.report_type ?? '',
    description: r.description ?? '',
    status: r.status ?? 'Pending',
    latitude: Number(r.latitude ?? 0),
    longitude: Number(r.longitude ?? 0),
    created_at: r.created_at ?? '',
    updated_at: r.updated_at ?? '',
    assigned_to: r.assigned_to ?? '',
    address: r.address ?? '',
    photo_url: r.photo_url ?? '',
    completion_photo_url: r.completion_photo_url ?? '',
    video_url: r.video_url ?? '',
    completion_video_url: r.completion_video_url ?? ''
  }));
}

// 新增：状态中文名兜底
function statusDisplay(code) {
  const mapCN = { 'Awaiting Review': '待审核' };
  const opt = document.querySelector(`#filter-status option[value="${code}"]`);
  return (opt?.textContent?.trim()) || mapCN[code] || code;
}

async function fetchReports() {
  const me = getCachedMe(); const role = me?.role || getRole();
  const filterStatus = document.getElementById('filter-status');
  const filterReportType = document.getElementById('filter-report-type');
  const searchDescription = document.getElementById('search-description');
  const sortBy = document.getElementById('sort-by');
  const sortOrder = document.getElementById('sort-order');
  const mapSection = document.getElementById('map-section');

  const params = new URLSearchParams();
  const statusVal = filterStatus?.value || 'All'; if (statusVal !== 'All') params.set('status', statusVal);
  const typeLike = (filterReportType?.value || '').trim(); if (typeLike) params.set('report_type', typeLike);
  const descLike = (searchDescription?.value || '').trim(); if (descLike) params.set('search', descLike);
  if (role === 'maintainer' && document.getElementById('assigned-only')?.checked) {
    const myname = me?.username || '';
    if (myname) params.set('assigned_to', myname);
  }
  params.set('sort_by', (sortBy?.value || 'created_at'));
  params.set('order', (sortOrder?.value || 'desc'));
  params.set('page', String(currentPage));
  params.set('per_page', String(reportsPerPage));

  let data;
  try {
    const resp = await apiFetch(`/reports?${params.toString()}`, { method:'GET' });
    data = await resp.json();
  } catch(e){
    console.warn('[fetchReports] 获取失败：', e);
    data = { reports: [], pagination:{ total_items:0, total_pages:1, current_page:1, per_page:reportsPerPage, has_next:false, has_prev:false } };
  }

  lastReportsPage = normalizeReports(Array.isArray(data.reports) ? data.reports : []);
  lastPagination = data.pagination || { total_pages:1, current_page:1, has_next:false, has_prev:false };
  updateDashboardKpis(lastReportsPage);
  renderReportsList();
  updatePaginationUI();
  if (leafletMapInited && mapSection && !mapSection.classList.contains('hidden')) {
    refreshMapMarkers(lastReportsPage);
  }
}

/* —— 列表渲染 —— */
function renderReportsList() {
  const box = document.getElementById('reports-list');
  if (!box) return;

  // 确保过滤下拉里有“待审核”
  const filterStatus = document.getElementById('filter-status');
  if (filterStatus && !filterStatus.querySelector('option[value="Awaiting Review"]')) {
    const opt = document.createElement('option');
    opt.value = 'Awaiting Review';
    opt.textContent = '待审核';
    filterStatus.appendChild(opt);
  }

  const list = Array.isArray(lastReportsPage) ? lastReportsPage : [];
  box.innerHTML = '';

  if (!list.length) {
    box.innerHTML = `<div class="empty">${t('no_data','暂无数据')}</div>`;
    triggerReveal();
    return;
  }

  const me = getCachedMe();
  const role = me?.role || getRole();
  const meName = me?.username || '';
  const canUpdateStatus = role === 'admin' || role === 'maintainer';
  const canAssign       = role === 'admin';
  const canDelete       = role === 'admin';

  const STATUS_OPTIONS = ['Pending', 'In Progress', 'Awaiting Review', 'Completed', 'Rejected'];

  const html = list.map(r => {
    const latOk = isFinite(r.latitude), lngOk = isFinite(r.longitude);
    const latlng = (latOk && lngOk) ? `${r.latitude.toFixed(6)}, ${r.longitude.toFixed(6)}` : '—';

    const statusSelectHtml = canUpdateStatus ? `
      <select class="status-select" data-id="${r.id}">
        ${STATUS_OPTIONS.map(s => `<option value="${s}" ${s === r.status ? 'selected' : ''}>${statusDisplay(s)}</option>`).join('')}
      </select>` : '';

    const assignHtml = canAssign ? `
      <input class="assign-input" type="text" placeholder="维护员用户名" value="${escapeHtml(r.assigned_to || '')}" data-id="${r.id}" />
      <button class="btn-success" data-action="assign" data-id="${r.id}">指派</button>` : '';

    // 维护员完工提交区
    const showCompletionArea = (role === 'maintainer' && r.assigned_to === meName && !['Completed','Rejected'].includes(r.status));
    const completionArea = showCompletionArea ? `
      <div class="completion-area" style="margin-top:8px;border-top:1px dashed #ddd;padding-top:8px">
        <div class="small" style="margin-bottom:6px">完工提交：</div>
        <input type="file" accept="image/*" data-id="${r.id}" name="completion_photo" />
        <input type="file" accept="video/*" data-id="${r.id}" name="completion_video" style="margin-left:8px" />
        <button class="btn-primary" data-action="upload-completion" data-id="${r.id}" style="margin-left:8px">提交完工（自动转为待审核）</button>
        ${r.status === 'Awaiting Review' ? `<div class="small" style="margin-top:6px;color:#888">已提交，等待管理员审核</div>` : ``}
      </div>` : '';

    // 管理员审核区（待审核）
    const reviewArea = (role === 'admin' && r.status === 'Awaiting Review') ? `
      <div class="review-area" style="margin-top:8px;border-top:1px dashed #ddd;padding-top:8px">
        <div class="small" style="margin-bottom:6px">审核区：</div>
        <button class="btn-success" data-action="approve" data-id="${r.id}">通过并删除</button>
        <button class="btn-warning" data-action="reject" data-id="${r.id}" style="margin-left:8px">驳回</button>
      </div>` : '';

    const actionsHtml = (canUpdateStatus || canAssign || canDelete) ? `
      <div class="report-actions">
        ${statusSelectHtml}
        ${canUpdateStatus ? `<button class="btn-primary" data-action="update-status" data-id="${r.id}">更新状态</button>` : ''}
        ${assignHtml}
        ${canDelete ? `<button class="delete-button" data-action="delete" data-id="${r.id}">删除</button>` : ''}
      </div>` : '';

    return `
      <div class="report-item reveal" data-id="${r.id}" data-lat="${r.latitude || ''}" data-lng="${r.longitude || ''}">
        <h4>${escapeHtml(r.report_type || '未命名故障')}</h4>
        <p>${escapeHtml(r.description || '')}</p>
        <p class="small">${t('status','状态')}：<strong>${escapeHtml(statusDisplay(r.status))}</strong> ｜ 坐标：${latlng}</p>
        <p class="small">${t('created','创建时间')}：${escapeHtml(safeDate(r.created_at))} ｜ ${t('updated','更新时间')}：${escapeHtml(safeDate(r.updated_at))}</p>
        ${r.assigned_to ? `<p class="small">指派给：${escapeHtml(r.assigned_to)}</p>` : ''}
        ${r.photo_url ? `
          <div class="img-wrap">
            <a href="/${r.photo_url}" target="_blank" rel="noopener">
              <img src="/${r.photo_url}" alt="现场图">
            </a>
          </div>` : ``}
        ${r.completion_photo_url ? `
          <div class="img-wrap">
            <div class="small" style="margin-top:6px">完工图片</div>
            <a href="/${r.completion_photo_url}" target="_blank" rel="noopener">
              <img src="/${r.completion_photo_url}" alt="完工图">
            </a>
          </div>` : ``}
        ${r.video_url ? `
          <div class="video-wrap" style="margin-top:8px">
            <video src="/${r.video_url}" controls preload="metadata" style="max-width:100%;border-radius:8px"></video>
          </div>` : ``}
        ${r.completion_video_url ? `
          <div class="video-wrap" style="margin-top:8px">
            <div class="small" style="margin-bottom:4px">完工视频</div>
            <video src="/${r.completion_video_url}" controls preload="metadata" style="max-width:100%;border-radius:8px"></video>
          </div>` : ``}
        ${completionArea}
        ${reviewArea}
        ${actionsHtml}
      </div>`;
  }).join('');

  box.innerHTML = html;
  triggerReveal();
}

/* —— KPI —— */
function updateDashboardKpis(list) {
  if (!Array.isArray(list)) list = [];
  const now = Date.now();
  const openCount = list.filter(r => !['Completed','Rejected'].includes(r.status)).length;
  const overdue = list.filter(r => {
    if (['Completed','Rejected'].includes(r.status)) return false;
    const t = r.created_at ? new Date(r.created_at).getTime() : null;
    return t && (now - t) > 48*3600*1000;
  }).length;
  setText('kpi-open', openCount);
  setText('kpi-overdue', overdue);
  function setText(id, val){ const el = document.getElementById(id); if (el) el.textContent = String(val); }
}

/* —— 分页 UI —— */
function updatePaginationUI() {
  const paginationControls = document.getElementById('pagination-controls');
  const pageInfoSpan = document.getElementById('page-info');
  const prevPageButton = document.getElementById('prev-page');
  const nextPageButton = document.getElementById('next-page');

  const p = lastPagination || { total_pages:1, current_page:1, has_next:false, has_prev:false };
  if (!paginationControls || !pageInfoSpan || !prevPageButton || !nextPageButton) return;

  if (p.total_pages > 1) {
    paginationControls.classList.remove('hidden');
    pageInfoSpan.textContent = `${t('page','页码')} ${p.current_page} / ${p.total_pages}`;
  } else {
    paginationControls.classList.add('hidden');
    pageInfoSpan.textContent = `${t('page','页码')} 1 / 1`;
  }
  prevPageButton.disabled = !p.has_prev;
  nextPageButton.disabled = !p.has_next;
}

/* ======================= 地图 ======================= */
let leafletMap = null;
let leafletMarkersLayer = null;
let leafletMapInited = false;

function initMapIfNeeded() {
  if (leafletMapInited) return;
  try {
    if (!window.L) throw new Error('Leaflet not loaded');
    leafletMap = L.map('map').setView([31.2304, 121.4737], 12);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19, attribution: '&copy; OpenStreetMap contributors'
    }).addTo(leafletMap);
    leafletMarkersLayer = L.layerGroup().addTo(leafletMap);
    leafletMapInited = true;
  } catch (err) { console.error('[initMap] 初始化 Leaflet 失败：', err); }
}
function refreshMapMarkers(items) {
  if (!leafletMapInited || !leafletMarkersLayer) return;
  leafletMarkersLayer.clearLayers();
  const pts = [];
  items.forEach(r => {
    if (isFinite(r.latitude) && isFinite(r.longitude)) {
      L.marker([r.latitude, r.longitude]).addTo(leafletMarkersLayer)
        .bindPopup(`<b>${escapeHtml(r.report_type || '')}</b><br/>${escapeHtml(r.description || '')}`);
      pts.push([r.latitude, r.longitude]);
    }
  });
  if (pts.length) { try { leafletMap.fitBounds(pts, { padding:[30,30] }); } catch{} }
}
async function toggleMapVisibility() {
  const mapSection = document.getElementById('map-section');
  const toggleMapCheckbox = document.getElementById('toggle-map');
  if (!mapSection || !toggleMapCheckbox) return;
  if (toggleMapCheckbox.checked) {
    mapSection.classList.remove('hidden');
    try { await ensureLeaflet(); } catch {}
    initMapIfNeeded();
    setTimeout(() => { try { leafletMap.invalidateSize(); } catch {} }, 50);
    refreshMapMarkers(lastReportsPage);
  } else mapSection.classList.add('hidden');
}

/* ======================= 报修提交 ======================= */
async function submitReport(formData) {
  const reportMessage = document.getElementById('report-message');
  const reportForm = document.getElementById('report-form');
  try {
    const lat = parseFloat(formData.get('latitude'));
    const lng = parseFloat(formData.get('longitude'));
    if (!isFinite(lat) || !isFinite(lng)) {
      return displayMessage(reportMessage,'请先填写（或自动获取）有效的经纬度',true);
    }
    const resp = await apiFetch('/reports', { method:'POST', body: formData });
    const data = await resp.json().catch(()=>({}));
    if (resp.status === 201) {
      const autoPart = data?.assigned_to ? ` 已自动指派给：${data.assigned_to}` : '';
      displayMessage(reportMessage, '提交成功！' + autoPart);
      reportForm?.reset();
      currentPage = 1;
      await fetchReports();
    } else {
      displayMessage(reportMessage, data.msg || '提交失败', true);
    }
  } catch(e){ console.error(e); displayMessage(reportMessage,'网络错误',true); }
}

/* ======================= API: 更新状态 / 指派 / 审核 / 删除 ======================= */
async function updateStatus(id, status) {
  const reportMessage = document.getElementById('report-message');
  try {
    const me = getCachedMe();
    const role = me?.role || getRole();

    if (role === 'maintainer') {
      const resp = await apiFetch(`/reports/${id}/maintainer`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      const data = await resp.json().catch(()=>({}));
      if (!resp.ok) throw new Error(data.msg || '状态更新失败（维护员）');
    } else if (role === 'admin') {
      const resp = await apiFetch(`/reports/${id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      const data = await resp.json().catch(()=>({}));
      if (!resp.ok) throw new Error(data.msg || '状态更新失败（管理员）');
    } else {
      throw new Error('只有管理员或维护员可以更新状态');
    }

    displayMessage(reportMessage, '状态已更新');
    await fetchReports();
  } catch (e) {
    displayMessage(reportMessage, e.message || '状态更新失败', true);
  }
}
async function assignMaintainer(id, username) {
  const reportMessage = document.getElementById('report-message');
  try {
    const resp = await apiFetch(`/reports/${id}/assign`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assigned_to: username })
    });
    const data = await resp.json().catch(()=>({}));
    if (!resp.ok) throw new Error(data.msg || '指派失败');
    displayMessage(reportMessage, `已指派给：${username}`);
    await fetchReports();
  } catch (e) {
    displayMessage(reportMessage, e.message || '指派失败', true);
  }
}
async function deleteReport(id) {
  const reportMessage = document.getElementById('report-message');
  try {
    if (!confirm('确认删除该报修？此操作不可恢复。')) return;
    const resp = await apiFetch(`/reports/${id}`, { method: 'DELETE' });
    if (!(resp.status === 204 || resp.ok)) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.msg || '删除失败');
    }
    displayMessage(reportMessage, '已删除该报修');
    if (lastReportsPage.length === 1 && lastPagination?.current_page > 1) currentPage = lastPagination.current_page - 1;
    await fetchReports();
  } catch (e) {
    displayMessage(reportMessage, e.message || '删除失败', true);
  }
}

// 新增：维护员提交完工材料（自动置为待审核）
async function uploadCompletion(id, photoFile, videoFile) {
  const reportMessage = document.getElementById('report-message');
  const fd = new FormData();
  if (photoFile) fd.append('completion_photo', photoFile);
  if (videoFile) fd.append('completion_video', videoFile);
  // 明确置为“待审核”
  fd.append('status', 'Awaiting Review');

  const resp = await apiFetch(`/reports/${id}/maintainer`, {
    method: 'POST',
    body: fd
  });
  const data = await resp.json().catch(()=>({}));
  if (!resp.ok) throw new Error(data.msg || '提交失败');
  displayMessage(reportMessage, '完工材料已提交，等待管理员审核');
  await fetchReports();
}

// 新增：管理员审核通过并自动删除
async function approveAndDelete(id) {
  const reportMessage = document.getElementById('report-message');
  const resp = await apiFetch(`/reports/${id}/approve`, { method: 'POST' });
  const data = await resp.json().catch(()=>({}));
  if (!resp.ok) throw new Error(data.msg || '审核失败');
  displayMessage(reportMessage, '审核通过并已删除该报修');
  await fetchReports();
}

/* ======================= Reveal + 数字动效 ======================= */
let revealObserver=null, countObserver=null;
function triggerReveal(){
  if (!revealObserver){
    revealObserver = new IntersectionObserver((entries, obs)=>{
      entries.forEach(entry=>{ if (entry.isIntersecting){ entry.target.classList.add('in'); obs.unobserve(entry.target); } });
    },{threshold:0.1});
  }
  document.querySelectorAll('.reveal:not(.in)').forEach(el=>revealObserver.observe(el));

  if (!countObserver){
    countObserver = new IntersectionObserver((entries, obs)=>{
      entries.forEach(entry=>{
        if (entry.isIntersecting){
          const el = entry.target;
          const target = parseFloat(el.getAttribute('data-count-to') || '0');
          const dur = 1200, t0 = performance.now();
          function frame(t){
            const p=Math.min(1,(t-t0)/dur);
            const val=target*(1-Math.pow(1-p,3));
            el.textContent=Number.isInteger(target)?Math.round(val):(val.toFixed(1));
            if(p<1)requestAnimationFrame(frame);
          }
          requestAnimationFrame(frame);
          obs.unobserve(el);
        }
      });
    },{threshold:0.4});
  }
  document.querySelectorAll('.num[data-count-to]').forEach(el=>countObserver.observe(el));
}

/* ======================= 事件绑定（DOM 就绪后） ======================= */
function bindUIEventsOnce() {
  // 顶部导航
  document.querySelectorAll('[data-nav]').forEach(a => {
    if (a.dataset.boundClick) return;
    a.dataset.boundClick = '1';
    a.addEventListener('click', (e) => {
      e.preventDefault();
      navTo(a.getAttribute('data-nav'));
    });
  });

  // 登录方式快捷入口
  document.querySelectorAll('[data-login]').forEach(el => {
    if (el.dataset.boundClick) return;
    el.dataset.boundClick = '1';
    el.addEventListener('click', (e)=>{
      e.preventDefault();
      const which = (el.getAttribute('data-login') || '').toLowerCase();
      navTo(which || 'login');
    });
  });

  // 登录/注册
  const userLoginForm = document.getElementById('user-login-form');
  const adminLoginForm = document.getElementById('admin-login-form');
  const maintLoginForm = document.getElementById('maintainer-login-form');
  const userRegisterForm = document.getElementById('user-register-form');

  if (userLoginForm && !userLoginForm.dataset.boundSubmit) {
    userLoginForm.dataset.boundSubmit = '1';
    userLoginForm.addEventListener('submit', (e)=>{
      e.preventDefault();
      const u = userLoginForm[0]?.value?.trim() || '';
      const p = userLoginForm[1]?.value || '';
      userLogin(u, p);
    });
  }
  if (maintLoginForm && !maintLoginForm.dataset.boundSubmit) {
    maintLoginForm.dataset.boundSubmit = '1';
    maintLoginForm.addEventListener('submit', (e)=>{
      e.preventDefault();
      const u = maintLoginForm[0]?.value?.trim() || '';
      const p = maintLoginForm[1]?.value || '';
      maintLogin(u, p);
    });
  }
  if (adminLoginForm && !adminLoginForm.dataset.boundSubmit) {
    adminLoginForm.dataset.boundSubmit = '1';
    adminLoginForm.addEventListener('submit', (e)=>{
      e.preventDefault();
      const u = adminLoginForm[0]?.value?.trim() || '';
      const p = adminLoginForm[1]?.value || '';
      loginAdmin(u, p);
    });
  }
  if (userRegisterForm && !userRegisterForm.dataset.boundSubmit) {
    userRegisterForm.dataset.boundSubmit = '1';
    userRegisterForm.addEventListener('submit', (e)=>{
      e.preventDefault();
      const u = userRegisterForm[0]?.value?.trim() || '';
      const p = userRegisterForm[1]?.value || '';
      const m = userRegisterForm[2]?.value?.trim() || '';
      userRegister(u, p, m);
    });
  }

  // —— 报修表单提交 —— //
  const reportForm = document.getElementById('report-form');
  const reportMsg  = document.getElementById('report-message');
  if (reportForm && !reportForm.dataset.boundSubmit) {
    reportForm.dataset.boundSubmit = '1';
    reportForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(reportForm);

      // 经纬度兜底
      const lat = parseFloat(fd.get('latitude'));
      const lng = parseFloat(fd.get('longitude'));
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
        try {
          const pos = await locateUploader(null);
          if (pos && Number.isFinite(pos.lat) && Number.isFinite(pos.lng)) {
            fd.set('latitude',  String(pos.lat));
            fd.set('longitude', String(pos.lng));
          }
        } catch {}
      }

      // 大图压缩
      const file = reportForm.querySelector('input[name="photo"]')?.files?.[0];
      if (file && /^image\//.test(file.type) && file.size > 1.5 * 1024 * 1024) {
        try {
          const small = await downscaleImage(file, 1600);
          fd.set('photo', small, small.name || 'photo.jpg');
        } catch {}
      }

      const submitBtn = reportForm.querySelector('[type="submit"]');
      if (submitBtn) submitBtn.disabled = true;
      if (reportMsg) displayMessage(reportMsg, '正在上传…', false);

      try { await submitReport(fd); }
      catch (err) {
        console.error('[submitReport]', err);
        displayMessage(reportMsg, err.message || '提交失败', true);
      }
      finally { if (submitBtn) submitBtn.disabled = false; }
    });
  }

  // 列表动作委托（含：审核/完工提交）
  const reportsList = document.getElementById('reports-list');
  if (reportsList && !reportsList.dataset.boundClick) {
    reportsList.dataset.boundClick = '1';
    reportsList.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      const id = btn.dataset.id;
      const action = btn.dataset.action;
      const card = e.target.closest('.report-item');
      const statusSel = card?.querySelector(`select.status-select[data-id="${id}"]`);
      const assignInp = card?.querySelector(`input.assign-input[data-id="${id}"]`);
      try {
        btn.disabled = true;
        if (action === 'update-status') {
          const nextStatus = statusSel?.value;
          if (!nextStatus) {
            const msgEl = document.getElementById('report-message');
            return displayMessage(msgEl, '请选择状态', true);
          }
          await updateStatus(id, nextStatus);
        }
        if (action === 'assign') {
          const toUser = (assignInp?.value || '').trim();
          if (!toUser) {
            const msgEl = document.getElementById('report-message');
            return displayMessage(msgEl, '请输入维护员用户名', true);
          }
          await assignMaintainer(id, toUser);
        }
        if (action === 'delete') {
          await deleteReport(id);
        }
        if (action === 'approve') {
          await approveAndDelete(id);
        }
        if (action === 'reject') {
          await updateStatus(id, 'Rejected');
        }
        if (action === 'upload-completion') {
          const photoInput = card.querySelector(`input[name="completion_photo"][data-id="${id}"]`);
          const videoInput = card.querySelector(`input[name="completion_video"][data-id="${id}"]`);
          const photoFile = photoInput?.files?.[0] || null;
          const videoFile = videoInput?.files?.[0] || null;
          if (!photoFile && !videoFile) {
            const msgEl = document.getElementById('report-message');
            return displayMessage(msgEl, '请至少选择一张完工图片或一个完工视频', true);
          }
          await uploadCompletion(id, photoFile, videoFile);
        }
      } finally {
        btn.disabled = false;
      }
    });
  }

  // 过滤/分页/地图/登出
  const applyFiltersButton = document.getElementById('apply-filters-button');
  if (applyFiltersButton && !applyFiltersButton.dataset.boundClick) {
    applyFiltersButton.dataset.boundClick = '1';
    applyFiltersButton.addEventListener('click', ()=>{ currentPage = 1; fetchReports(); });
  }
  const assignedOnlyCheckbox = document.getElementById('assigned-only');
  if (assignedOnlyCheckbox && !assignedOnlyCheckbox.dataset.boundChange) {
    assignedOnlyCheckbox.dataset.boundChange = '1';
    assignedOnlyCheckbox.addEventListener('change', ()=>{ currentPage = 1; fetchReports(); });
  }
  const sortBy = document.getElementById('sort-by');
  if (sortBy && !sortBy.dataset.boundChange) {
    sortBy.dataset.boundChange = '1';
    sortBy.addEventListener('change', ()=>{ currentPage = 1; fetchReports(); });
  }
  const sortOrder = document.getElementById('sort-order');
  if (sortOrder && !sortOrder.dataset.boundChange) {
    sortOrder.dataset.boundChange = '1';
    sortOrder.addEventListener('change', ()=>{ currentPage = 1; fetchReports(); });
  }
  const prevPageButton = document.getElementById('prev-page');
  if (prevPageButton && !prevPageButton.dataset.boundClick) {
    prevPageButton.dataset.boundClick = '1';
    prevPageButton.addEventListener('click', ()=>{ if (lastPagination?.has_prev) { currentPage = Math.max(1,currentPage-1); fetchReports(); } });
  }
  const nextPageButton = document.getElementById('next-page');
  if (nextPageButton && !nextPageButton.dataset.boundClick) {
    nextPageButton.dataset.boundClick = '1';
    nextPageButton.addEventListener('click', ()=>{ if (lastPagination?.has_next) { currentPage += 1; fetchReports(); } });
  }
  const toggleMapCheckbox = document.getElementById('toggle-map');
  if (toggleMapCheckbox && !toggleMapCheckbox.dataset.boundChange) {
    toggleMapCheckbox.dataset.boundChange = '1';
    toggleMapCheckbox.addEventListener('change', toggleMapVisibility);
  }
  const logoutButton = document.getElementById('logout-button');
  if (logoutButton && !logoutButton.dataset.boundClick) {
    logoutButton.dataset.boundClick = '1';
    logoutButton.addEventListener('click', ()=>{
      clearAuth();
      updateNavAndHeroForAuth();
      navTo('home');
      const reportsList = document.getElementById('reports-list');
      if (reportsList) reportsList.innerHTML='';
      document.getElementById('pagination-controls')?.classList.add('hidden');
      document.getElementById('map-section')?.classList.add('hidden');
      const tgl = document.getElementById('toggle-map'); if (tgl) tgl.checked = false;
      updateWhoAmI();
    });
  }
}

/* ======================= 启动 ======================= */
async function initApp(){
  updateNavAndHeroForAuth();
  if (isAuthenticated()) await fetchMe();
  updateNavAndHeroForAuth();
  routeFromHash();
  triggerReveal();
}
document.addEventListener('DOMContentLoaded', ()=>{
  bindUIEventsOnce();
  window.addEventListener('hashchange', routeFromHash);
  initApp();
});

/* ======================= 定位（浏览器 → EXIF → IP） ======================= */
const PI = Math.PI, a = 6378245.0, ee = 0.00669342162296594323;
function outOfChina(lng, lat){ return lng<72.004||lng>137.8347||lat<0.8293||lat>55.8271; }
function transformLat(x,y){ let ret=-100+2*x+3*y+0.2*y*y+0.1*x*y+0.2*Math.sqrt(Math.abs(x)); ret+=(20*Math.sin(6*x*PI)+20*Math.sin(2*x*PI))*2/3; ret+=(20*Math.sin(y*PI)+40*Math.sin(y/3*PI))*2/3; ret+=(160*Math.sin(y*PI/12)+320*Math.sin(y*PI/30))*2/3; return ret; }
function transformLng(x,y){ let ret=300+x+2*y+0.1*x*x+0.1*x*y+0.1*Math.sqrt(Math.abs(x)); ret+=(20*Math.sin(6*x*PI)+20*Math.sin(2*x*PI))*2/3; ret+=(20*Math.sin(x*PI)+40*Math.sin(x/3*PI))*2/3; ret+=(150*Math.sin(x*PI/12)+300*Math.sin(x*PI/30))*2/3; return ret; }
function wgs84ToGcj02(lng, lat){ if (outOfChina(lng, lat)) return [lng, lat]; let dLat=transformLat(lng-105.0,lat-35.0); let dLng=transformLng(lng-105.0,lat-35.0); const radLat=lat/180.0*PI; let magic=Math.sin(radLat); magic=1-ee*magic*magic; const sqrtMagic=Math.sqrt(magic); dLat=(dLat*180.0)/((a*(1-ee))/(magic*sqrtMagic)*PI); dLng=(dLng*180.0)/(a/ sqrtMagic * Math.cos(radLat) * PI); return [lng + dLng, lat + dLat]; }
async function reverseGeocode(lng, lat){ try{ const url=`https://restapi.amap.com/v3/geocode/regeo?key=${GAODE_KEY}&location=${lng},${lat}&extensions=base`; const res=await fetch(url); const data=await res.json(); if (data.status==='1') return data.regeocode.formatted_address||''; }catch{} return ''; }
async function locateUploader(file){
  try{
    const pos=await new Promise((resolve,reject)=>navigator.geolocation.getCurrentPosition(resolve,reject,{enableHighAccuracy:true,timeout:10000}));
    const [lng,lat]=wgs84ToGcj02(pos.coords.longitude,pos.coords.latitude);
    return { lng, lat, address: await reverseGeocode(lng, lat) };
  }catch(e){}
  if (file && typeof exifr!=='undefined' && /^image\//.test(file.type)){
    try{
      const gps=await exifr.gps(file);
      if (gps && gps.longitude && gps.latitude){
        const [lng,lat]=wgs84ToGcj02(gps.longitude,gps.latitude);
        return { lng, lat, address: await reverseGeocode(lng, lat) };
      }
    }catch(e){}
  }
  try{
    const r=await fetch(`https://restapi.amap.com/v3/ip?key=${GAODE_KEY}`);
    const data=await r.json();
    if (data.status==='1' && data.rectangle){
      const [lng,lat]=data.rectangle.split(';')[0].split(',').map(Number);
      return { lng, lat, address: (data.province||'') + (data.city||'') };
    }
  }catch(e){}
  throw new Error('无法定位');
}

// 页面加载自动定位 + 选图触发 AI（仅图片）
document.addEventListener('DOMContentLoaded', ()=>{
  const latInput  = document.querySelector('input[name="latitude"]');
  const lngInput  = document.querySelector('input[name="longitude"]');
  const fileInput = document.querySelector('input[name="photo"], #photo, input[type="file"][accept^="image"]');

  const hint = ()=> (document.getElementById('ai-hint')
                  || document.getElementById('report-message')
                  || document.querySelector('.message'));

  async function fillPos(pos){
    if (!pos || !latInput || !lngInput) return;
    latInput.value = Number(pos.lat).toFixed(6);
    lngInput.value = Number(pos.lng).toFixed(6);
  }

  (async ()=>{
    try { const pos = await locateUploader(null); await fillPos(pos); }
    catch(e){ console.warn('自动定位失败', e); }
  })();

  if (!fileInput) {
    console.warn('[AI] 未找到图片上传控件');
    return;
  }

  fileInput.addEventListener('change', async ()=>{
    const file = fileInput.files?.[0]; if (!file) return;
    if (!/^image\//.test(file.type)) return; // 只对图片启用

    try { await ensureExifr(); } catch(e) { console.warn('exifr加载失败', e); }

    try { const pos = await locateUploader(file); await fillPos(pos); }
    catch(e){ console.warn('照片定位失败', e); }

    const msg = hint(); if (msg) displayMessage(msg, '正在识别图片…', false);
    try {
      const res = await aiRecognize(file);
      writeAiResultToForm(res);
      if (msg) displayMessage(msg, 'AI 识别完成', false);
    } catch (e) {
      console.error('[AI识别失败]', e);
      if (msg) displayMessage(msg, 'AI 识别失败：' + (e.message || e), true);
    }
  });
});

/* ======================= 强制打开地图（进入系统页） ======================= */
async function forceMapOn() {
  const mapSection = document.getElementById('map-section');
  if (mapSection) mapSection.classList.remove('hidden');
  const toggle = document.getElementById('toggle-map');
  if (toggle) { toggle.checked = true; }
  try { await ensureLeaflet(); } catch {}
  initMapIfNeeded();
  setTimeout(()=> { try { leafletMap.invalidateSize(); } catch {} }, 50);
  try { refreshMapMarkers(Array.isArray(lastReportsPage) ? lastReportsPage : []); } catch {}
}

/* ======================= AI 自动识别（统一入口） ======================= */
const AI_CONFIG = {
  providerOrder: ['backend'],
  backendPath: '/ai/vision',
  backendCandidates: ['/ai/vision','/api/ai/vision','/api/ai/analyze','/ai/analyze'],
  maxSide: 1280,
  lang: (navigator.language || 'zh').toLowerCase().startsWith('zh') ? 'zh' : 'en'
};
function aiHintEl(){
  return document.getElementById('ai-hint')
      || document.getElementById('report-message')
      || document.querySelector('.message');
}
async function downscaleImage(file, maxSide = 1280) {
  if (!file || !/^image\//.test(file.type)) return file;
  const img = await new Promise((res, rej)=>{
    const i = new Image(); i.onload = ()=>res(i); i.onerror = rej;
    i.src = URL.createObjectURL(file);
  });
  const w = img.naturalWidth, h = img.naturalHeight;
  const scale = Math.min(1, maxSide / Math.max(w, h));
  if (scale >= 1) return file;
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(w * scale); canvas.height = Math.round(h * scale);
  const ctx = canvas.getContext('2d'); ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise(res=>canvas.toBlob(res, 'image/jpeg', 0.85));
  return new File([blob], (file.name || 'photo') + '.jpg', { type:'image/jpeg' });
}
async function fileToDataURL(file){
  return await new Promise((res, rej)=>{
    const r = new FileReader(); r.onload = ()=>res(r.result); r.onerror = rej; r.readAsDataURL(file);
  });
}
// —— 后端：尝试一组候选路径（含 AI_CONFIG.backendPath）
async function aiViaBackend(file, extras = {}) {
  const fd = new FormData();
  fd.append('image', file);
  fd.append('lang', AI_CONFIG.lang);
  Object.entries(extras||{}).forEach(([k,v])=>fd.append(k,String(v)));

  const headers = {}; const tk = getToken(); if (tk) headers['Authorization'] = `Bearer ${tk}`;
  const tried = new Set();
  const candidates = [AI_CONFIG.backendPath, ...(AI_CONFIG.backendCandidates||[])].filter(Boolean);

  const errors = [];
  for (const path of candidates) {
    const endpoint = `${BASE_URL || ''}${path}`;
    if (tried.has(endpoint)) continue;
    tried.add(endpoint);
    try{
      const resp = await fetch(endpoint, { method:'POST', body: fd, headers, credentials:'include' });
      if (!resp.ok) {
        const txt = await resp.text().catch(()=> '');
        throw new Error(`${resp.status} ${txt?.slice(0,120) || ''}`);
      }
      let j = await resp.json().catch(()=> ({}));
      if (j?.data && typeof j.data === 'object') j = j.data;
      return j;
    }catch(e){
      errors.push(`${endpoint} -> ${e.message||e}`);
    }
  }
  throw new Error(errors.join(' | '));
}
// —— OpenAI（可选）
// —— OpenAI（可选）
async function aiViaOpenAI(file){
  if (!window.OPENAI_API_KEY) throw new Error('缺少 OPENAI_API_KEY');
  const b64 = await fileToDataURL(file);

  const payload = {
    model: "gpt-4o-mini",
    temperature: 0.2,
    messages: [{
      role: "user",
      content: [
        {
          type: "text",
          text: `你是城市报修助手。请从图片中判断故障类型并用${AI_CONFIG.lang==='zh'?'中文':'English'}返回 JSON：
{"type":"","confidence":0.0,"severity":1,"short_description":"","long_description":"","suggested_report_type":""}
只返回 JSON，不要解释。`
        },
        { type: "image_url", image_url: { url: b64 } }
      ]
    }]
  };

  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${window.OPENAI_API_KEY}`
    },
    body: JSON.stringify(payload)
  });

  if (!resp.ok) {
    const txt = await resp.text().catch(() => "");
    throw new Error(`${resp.status} ${txt.slice(0,120)}`);
  }

  const j = await resp.json();
  const text = j?.choices?.[0]?.message?.content?.trim() || "{}";
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

// —— 计算告警 —— //
function computeAlertsFromReports(list){
  const now = Date.now();
  const out = [];
  (list || []).forEach(r=>{
    if (!r) return;
    const done = r.status === 'Completed' || r.status === 'Rejected';
    if (done) return;

    const created = r.created_at ? new Date(r.created_at).getTime() : 0;
    const ageH = created ? (now - created) / 3600000 : 0;

    if (!r.assigned_to) {
      out.push({ level:'warn', id:r.id, text:`#${r.id} 未指派`, ts: created });
    }
    if (r.status === 'Pending' && ageH > 24) {
      out.push({ level:'danger', id:r.id, text:`#${r.id} 待处理超过 24 小时`, ts: created });
    }
    if (r.status === 'In Progress' && ageH > 48) {
      out.push({ level:'danger', id:r.id, text:`#${r.id} 处理超过 48 小时`, ts: created });
    }
  });

  // 先高优先级，再时间倒序，最多 8 条
  out.sort((a,b)=>{
    const lv = { danger:2, warn:1 };
    const d = (lv[b.level]||0) - (lv[a.level]||0);
    if (d!==0) return d;
    return (b.ts||0) - (a.ts||0);
  });
  return out.slice(0,8);
}

// —— 渲染告警（容器优先找 #alerts-list，其次 [data-alerts]） —— //
function renderAlerts(list){
  const box = document.getElementById('alerts-list') 
           || document.getElementById('alerts') 
           || document.querySelector('[data-alerts]');
  if (!box) return;

  const items = computeAlertsFromReports(list);
  if (!items.length){
    box.innerHTML = `<div class="alert-empty">暂无告警</div>`;
    return;
  }
  box.innerHTML = items.map(it=>`
    <div class="alert-item ${it.level}">
      <div class="alert-main">
        <span class="badge">${it.level==='danger' ? '高' : '提示'}</span>
        <span>${escapeHtml(it.text)}</span>
      </div>
      <button class="btn-link" data-jump-report="${it.id}">查看</button>
    </div>
  `).join('');

  // 一次性绑定跳转
  box.addEventListener('click', (e)=>{
    const btn = e.target.closest('[data-jump-report]');
    if (!btn) return;
    const id = btn.getAttribute('data-jump-report');
    const card = document.querySelector(`.report-item[data-id="${id}"]`);
    if (card){
      card.scrollIntoView({ behavior:'smooth', block:'start' });
      card.classList.add('highlight');
      setTimeout(()=>card.classList.remove('highlight'), 1500);
    }
  }, { once:true });
}

