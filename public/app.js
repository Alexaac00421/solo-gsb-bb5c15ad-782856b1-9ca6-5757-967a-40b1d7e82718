'use strict';

const state = {
  token: localStorage.getItem('token') || null,
  user: JSON.parse(localStorage.getItem('user') || 'null'),
  domains: [],
  currentDomain: null,
  currentFamily: 4,
  selectedPrefix: null,
};

const $ = (sel) => document.querySelector(sel);

async function api(method, path, body, { idem = false } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (idem) headers['Idempotency-Key'] = crypto.randomUUID();
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || data.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    err.replay = res.headers.get('Idempotent-Replay') === 'true';
    throw err;
  }
  data.__replay = res.headers.get('Idempotent-Replay') === 'true';
  return data;
}

function toast(message, kind = 'info', requestNo) {
  const box = document.createElement('div');
  box.className = `toast-item ${kind}`;
  box.textContent = message;
  if (requestNo) {
    const r = document.createElement('span');
    r.className = 'req';
    r.textContent = (arguments[3] ? 'replayed · ' : '') + requestNo;
    box.appendChild(r);
  }
  $('#toast').appendChild(box);
  setTimeout(() => box.remove(), 6000);
}

function showView() {
  if (state.user) {
    $('#loginView').hidden = true;
    $('#appView').hidden = false;
    document.querySelectorAll('.adminOnly').forEach((el) => {
      el.hidden = state.user.role !== 'admin';
    });
    $('#userbox').innerHTML =
      `<span>${escapeHtml(state.user.username)} (${state.user.role === 'admin' ? '管理员' : '持有人'})</span>
       <button id="logoutBtn">退出</button>`;
    $('#logoutBtn').onclick = () => {
      localStorage.clear();
      location.reload();
    };
    loadDomains();
  } else {
    $('#loginView').hidden = false;
    $('#appView').hidden = true;
    $('#userbox').innerHTML = '';
  }
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- auth ----------

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const data = await api('POST', '/api/login', {
      username: fd.get('username'),
      password: fd.get('password'),
    });
    state.token = data.token;
    state.user = data.user;
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    showView();
    toast('登录成功', 'ok');
  } catch (err) {
    toast(err.message, 'err');
  }
});

$('#registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    await api('POST', '/api/register', {
      username: fd.get('username'),
      password: fd.get('password'),
    });
    toast('注册成功，请登录', 'ok');
    e.target.reset();
  } catch (err) {
    toast(err.message, 'err');
  }
});

// ---------- domains ----------

async function loadDomains() {
  const data = await api('GET', '/api/domains');
  state.domains = data.domains;
  renderDomains();
  if (state.currentDomain && !state.domains.find((d) => d.id === state.currentDomain.id)) {
    state.currentDomain = null;
  }
  if (!state.currentDomain && state.domains.length) {
    selectDomain(state.domains[0]);
  } else if (state.currentDomain) {
    loadTree();
  }
}

function renderDomains() {
  $('#domainList').innerHTML = state.domains
    .map(
      (d) => `<div class="domain-item ${state.currentDomain?.id === d.id ? 'active' : ''}" data-id="${d.id}">
        #${d.id} ${escapeHtml(d.name)}
        <span class="sub">${escapeHtml(d.description || '')}</span>
      </div>`,
    )
    .join('');
  document.querySelectorAll('.domain-item').forEach((el) => {
    el.onclick = () => selectDomain(state.domains.find((d) => d.id === Number(el.dataset.id)));
  });
}

function selectDomain(d) {
  state.currentDomain = d;
  state.selectedPrefix = null;
  renderDomains();
  $('#rootFormWrap').hidden = state.user.role !== 'admin';
  loadTree();
}

$('#domainForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    await api('POST', '/api/domains', { name: fd.get('name'), description: fd.get('description') }, { idem: true });
    e.target.reset();
    await loadDomains();
    toast('地址域已创建', 'ok');
  } catch (err) {
    toast(err.message, 'err');
  }
});

$('#rootForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.currentDomain) return toast('请先选择地址域', 'err');
  const fd = new FormData(e.target);
  try {
    const data = await api(
      'POST',
      '/api/roots',
      {
        domain_id: state.currentDomain.id,
        cidr: fd.get('cidr'),
        purpose: fd.get('purpose'),
      },
      { idem: true },
    );
    toast(`根前缀 ${data.prefix.cidr} 已创建`, 'ok', data.request_no, data.__replay);
    e.target.reset();
    renderFromTree(data.tree);
  } catch (err) {
    toast(`${err.message}${err.data?.request_no ? ' (' + err.data.request_no + ')' : ''}`, 'err');
  }
});

// ---------- tree ----------

$('#familySelect').addEventListener('change', (e) => {
  state.currentFamily = Number(e.target.value);
  loadTree();
});
$('#refreshBtn').onclick = () => loadTree();

async function loadTree() {
  if (!state.currentDomain) {
    $('#tree').innerHTML = '<p class="hint">尚无地址域或未选择。</p>';
    return;
  }
  try {
    const data = await api(
      'GET',
      `/api/domains/${state.currentDomain.id}/tree?family=${state.currentFamily}`,
    );
    renderFromTree(data.tree);
  } catch (err) {
    toast(err.message, 'err');
  }
}

function renderFromTree(tree) {
  lastTree = tree;
  const el = $('#tree');
  if (!tree.length) {
    el.innerHTML = '<p class="hint">该域此地址族还没有根前缀。</p>';
    return;
  }
  el.innerHTML = '<ul>' + tree.map(renderNode).join('') + '</ul>';
  el.querySelectorAll('.tree-node').forEach((node) => {
    node.onclick = () => {
      const id = Number(node.dataset.id);
      selectPrefix(id, node.dataset.cidr, node.dataset.holder);
    };
  });
}

function renderNode(n) {
  const selected = state.selectedPrefix?.id === n.id ? 'selected' : '';
  const typeLabel = { root: '根', allocation: '分配', reservation: '保留' }[n.type] || n.type;
  const children = n.children?.length ? `<ul>${n.children.map(renderNode).join('')}</ul>` : '';
  return `<li>
    <div class="tree-node ${selected}" data-id="${n.id}" data-cidr="${escapeHtml(n.cidr)}" data-holder="${n.holder_id}">
      <span class="badge ${n.type}">${typeLabel}</span>
      <span>${escapeHtml(n.cidr)}</span>
      <span class="meta">#${n.id}${n.purpose ? ' · ' + escapeHtml(n.purpose) : ''}</span>
      <span class="owner">holder #${n.holder_id}</span>
    </div>
    ${children}
  </li>`;
}

function findInTree(nodes, id) {
  for (const n of nodes) {
    if (n.id === id) return n;
    const hit = findInTree(n.children || [], id);
    if (hit) return hit;
  }
  return null;
}

let lastTree = [];

function selectPrefix(id, cidr, holderId) {
  state.selectedPrefix = { id, cidr, holderId: Number(holderId) };
  $('#allocParent').value = id;
  $('#releasePrefix').value = id;
  loadTree();
}

// ---------- actions ----------

$('#allocateForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.currentDomain) return toast('请先选择地址域', 'err');
  const fd = new FormData(e.target);
  const payload = {
    domain_id: state.currentDomain.id,
    parent_id: Number(fd.get('parent_id')),
    target_len: Number(fd.get('target_len')),
    purpose: fd.get('purpose'),
  };
  const holderId = fd.get('holder_id');
  if (holderId) payload.holder_id = Number(holderId);
  try {
    const data = await api('POST', '/api/prefixes/allocate', payload, { idem: true });
    toast(
      `已分配 ${data.prefix.cidr}（编号 #${data.prefix.id}）${data.__replay ? '（幂等重试）' : ''}`,
      'ok',
      data.request_no,
    );
    showResult(data);
    renderFromTree(data.tree);
    e.target.reset();
    $('#allocParent').value = state.selectedPrefix?.id || '';
  } catch (err) {
    toast(`${err.message}${err.data?.request_no ? ' (' + err.data.request_no + ')' : ''}`, 'err');
  }
});

$('#reserveForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.currentDomain) return toast('请先选择地址域', 'err');
  const fd = new FormData(e.target);
  try {
    const data = await api(
      'POST',
      '/api/prefixes/reserve',
      {
        domain_id: state.currentDomain.id,
        cidr: fd.get('cidr'),
        purpose: fd.get('purpose'),
      },
      { idem: true },
    );
    toast(`已保留 ${data.prefix.cidr}（编号 #${data.prefix.id}）`, 'ok', data.request_no, data.__replay);
    showResult(data);
    renderFromTree(data.tree);
    e.target.reset();
  } catch (err) {
    toast(err.message, 'err');
  }
});

$('#releaseForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const id = Number(fd.get('prefix_id'));
  if (!id) return toast('请先在前缀树中选择一个前缀', 'err');
  if (!confirm(`确认释放前缀 #${id}？释放后地址可被重新分配，但历史记录仍保留。`)) return;
  try {
    const data = await api(
      'POST',
      `/api/prefixes/${id}/release`,
      { note: fd.get('note') },
      { idem: true },
    );
    toast(`已释放 ${data.prefix.cidr}`, 'ok', data.request_no, data.__replay);
    showResult(data);
    renderFromTree(data.tree);
    state.selectedPrefix = null;
  } catch (err) {
    toast(err.message, 'err');
  }
});

function showResult(data) {
  $('#actionResult').innerHTML =
    `<div class="result-box">${escapeHtml(
      JSON.stringify(
        {
          request_no: data.request_no,
          prefix: data.prefix,
        },
        null,
        2,
      ),
    )}</div>`;
}

// ---------- boot ----------
showView();
