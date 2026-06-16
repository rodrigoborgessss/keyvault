/*
 * app.js — lógica da interface do KeyVault
 *
 * Tudo o que é sensível (master password, cofre em claro) vive só em memória
 * e desaparece ao bloquear. Para o servidor só vai o blob cifrado.
 */

const $ = (sel) => document.querySelector(sel);

const state = {
  master: null,
  vault: null, // { entries: [...] }
  selectedId: null,
  search: '',
  isNew: false
};

const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutos de inatividade
let autoLockTimer = null;
let clipboardTimer = null;

/* ---------------- utilidades ---------------- */

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function toast(msg) {
  const t = $('#toast');
  $('#toastMsg').textContent = msg;
  t.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('show'), 2200);
}

async function copyText(text, { autoClear = false } = {}) {
  try {
    await navigator.clipboard.writeText(text);
    toast(autoClear ? 'Copiado — limpa em 20s' : 'Copiado');
    if (autoClear) {
      clearTimeout(clipboardTimer);
      clipboardTimer = setTimeout(() => {
        navigator.clipboard.writeText('').catch(() => {});
      }, 20000);
    }
  } catch {
    toast('Não foi possível copiar');
  }
}

function resetAutoLock() {
  clearTimeout(autoLockTimer);
  if (state.master) {
    autoLockTimer = setTimeout(lock, AUTO_LOCK_MS);
  }
}

/* ---------------- arranque / bloqueio ---------------- */

async function init() {
  ['click', 'keydown', 'mousemove'].forEach((ev) =>
    document.addEventListener(ev, resetAutoLock, { passive: true })
  );

  let data;
  try {
    data = await Storage.load();
  } catch {
    $('#lockSub').textContent = 'Erro ao aceder ao armazenamento do cofre.';
    return;
  }

  if (data.exists) {
    showLock('unlock');
  } else {
    showLock('setup');
  }
}

function showLock(mode) {
  $('#app').classList.remove('active');
  $('#lockScreen').classList.remove('hidden');
  $('#masterInput').value = '';
  $('#confirmInput').value = '';
  $('#lockError').textContent = '';

  if (mode === 'setup') {
    $('#lockSub').textContent = 'Cria a tua master password para começar.';
    $('#masterLabel').textContent = 'Nova master password';
    $('#confirmField').style.display = 'block';
    $('#unlockBtn').textContent = 'Criar cofre';
    $('#lockHint').textContent =
      'Esta password cifra tudo. Não é guardada em lado nenhum e não pode ser recuperada — se a perderes, perdes o cofre.';
  } else {
    $('#lockSub').textContent = 'Introduz a master password para abrir o cofre.';
    $('#masterLabel').textContent = 'Master password';
    $('#confirmField').style.display = 'none';
    $('#unlockBtn').textContent = 'Desbloquear';
    $('#lockHint').textContent = '';
  }
  $('#lockScreen').dataset.mode = mode;
  $('#masterInput').focus();
}

async function handleUnlock() {
  const mode = $('#lockScreen').dataset.mode;
  const master = $('#masterInput').value;
  $('#lockError').textContent = '';

  if (!master) {
    $('#lockError').textContent = 'Escreve a master password.';
    return;
  }

  if (mode === 'setup') {
    if (master.length < 8) {
      $('#lockError').textContent = 'Usa pelo menos 8 caracteres.';
      return;
    }
    if (master !== $('#confirmInput').value) {
      $('#lockError').textContent = 'As passwords não coincidem.';
      return;
    }
    state.master = master;
    state.vault = { entries: [] };
    await saveVault();
    enterApp();
    return;
  }

  // unlock
  try {
    const data = await Storage.load();
    const vault = await decryptVault(data.blob, master);
    state.master = master;
    state.vault = vault;
    enterApp();
    // migração silenciosa: cofres antigos (PBKDF2) passam a Argon2id ao reabrir
    if (isLegacyKdf(data.blob)) {
      await saveVault();
      toast('Cofre atualizado para Argon2id');
    }
  } catch {
    $('#lockError').textContent = 'Master password incorreta.';
    $('#masterInput').select();
  }
}

function enterApp() {
  $('#lockScreen').classList.add('hidden');
  $('#app').classList.add('active');
  state.selectedId = null;
  state.isNew = false;
  renderList();
  renderEmpty();
  resetAutoLock();
}

function lock() {
  state.master = null;
  state.vault = null;
  state.selectedId = null;
  clearTimeout(autoLockTimer);
  showLock('unlock');
}

/* ---------------- persistência ---------------- */

async function saveVault() {
  const blob = await encryptVault(state.vault, state.master);
  try {
    await Storage.save(blob);
  } catch {
    toast('Erro ao guardar');
  }
}

/* ---------------- lista lateral ---------------- */

function filteredEntries() {
  const q = state.search.trim().toLowerCase();
  const list = state.vault.entries.slice().sort((a, b) =>
    a.name.localeCompare(b.name, 'pt', { sensitivity: 'base' })
  );
  if (!q) return list;
  return list.filter((e) =>
    [e.name, e.username, e.url].some((f) => (f || '').toLowerCase().includes(q))
  );
}

function renderList() {
  const list = filteredEntries();
  const el = $('#entriesList');

  if (state.vault.entries.length === 0) {
    el.innerHTML = '<div class="empty-list">O cofre está vazio.<br>Cria a primeira entrada.</div>';
    return;
  }
  if (list.length === 0) {
    el.innerHTML = '<div class="empty-list">Nada encontrado para essa procura.</div>';
    return;
  }

  el.innerHTML = list.map((e) => {
    const initial = (e.name || '?').trim().charAt(0).toUpperCase();
    const flag = e.pwnedCount > 0
      ? '<span class="entry-flag pwned" title="Encontrada em fugas"></span>'
      : '';
    const sel = e.id === state.selectedId ? ' selected' : '';
    return `
      <div class="entry-item${sel}" data-id="${e.id}">
        <div class="entry-avatar">${escapeHtml(initial)}</div>
        <div class="entry-meta">
          <div class="entry-name">${escapeHtml(e.name)}</div>
          <div class="entry-user">${escapeHtml(e.username || '—')}</div>
        </div>
        ${flag}
      </div>`;
  }).join('');

  el.querySelectorAll('.entry-item').forEach((node) =>
    node.addEventListener('click', () => selectEntry(node.dataset.id))
  );
}

/* ---------------- painel principal ---------------- */

function renderEmpty() {
  $('#mainPanel').innerHTML = `
    <div class="placeholder-panel">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
      <h2>Seleciona uma entrada</h2>
      <p>Ou cria uma nova para guardar credenciais cifradas.</p>
    </div>`;
}

function selectEntry(id) {
  state.selectedId = id;
  state.isNew = false;
  const entry = state.vault.entries.find((e) => e.id === id);
  renderDetail(entry);
  renderList();
}

function newEntry() {
  state.selectedId = null;
  state.isNew = true;
  renderDetail({ id: null, name: '', url: '', username: '', password: '', notes: '' });
  renderList();
}

function renderDetail(entry) {
  const isNew = state.isNew;
  $('#mainPanel').innerHTML = `
    <div class="panel-head">
      <h2 id="detailTitle">${isNew ? 'Nova entrada' : escapeHtml(entry.name)}</h2>
      <div class="panel-actions">
        ${isNew ? '' : '<button class="btn btn-danger btn-sm" id="deleteBtn">Eliminar</button>'}
        <button class="btn btn-primary btn-sm" id="saveBtn">Guardar</button>
      </div>
    </div>

    <div class="detail-field">
      <label for="fName">Nome / serviço</label>
      <input type="text" id="fName" placeholder="ex: GitHub" />
    </div>

    <div class="detail-field">
      <label for="fUrl">Endereço (opcional)</label>
      <input type="url" id="fUrl" placeholder="https://…" />
    </div>

    <div class="detail-field">
      <label for="fUser">Utilizador / email</label>
      <input type="text" id="fUser" placeholder="pedro@exemplo.pt" autocomplete="off" />
    </div>

    <div class="detail-field">
      <label for="fPass">Password</label>
      <div class="pw-row">
        <input type="password" id="fPass" placeholder="••••••••" autocomplete="off" />
        <button class="icon-btn" id="revealBtn" title="Mostrar / esconder">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
        <button class="icon-btn" id="genFieldBtn" title="Gerar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>
        </button>
        <button class="icon-btn" id="copyPassBtn" title="Copiar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
        </button>
      </div>
      <div class="strength">
        <div class="strength-bar"><div class="strength-fill" id="strengthFill"></div></div>
        <div class="strength-label" id="strengthLabel">—</div>
      </div>
      <div style="margin-top:14px">
        <button class="btn btn-ghost btn-sm" id="checkPwnedBtn">
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z"/></svg>
          Verificar se foi exposta
        </button>
      </div>
      <div class="pwned-box" id="pwnedBox"></div>
    </div>

    <div class="detail-field">
      <label for="fNotes">Notas</label>
      <textarea id="fNotes" placeholder="Notas opcionais…"></textarea>
    </div>
  `;

  // popular valores (via propriedade, evita problemas de escaping)
  $('#fName').value = entry.name || '';
  $('#fUrl').value = entry.url || '';
  $('#fUser').value = entry.username || '';
  $('#fPass').value = entry.password || '';
  $('#fNotes').value = entry.notes || '';

  bindDetail(entry);
  updateStrength($('#fPass').value);
}

function bindDetail(entry) {
  const passInput = $('#fPass');

  $('#revealBtn').addEventListener('click', () => {
    passInput.type = passInput.type === 'password' ? 'text' : 'password';
  });

  $('#genFieldBtn').addEventListener('click', () => {
    const pw = generatePassword({ length: 18 });
    passInput.value = pw;
    passInput.type = 'text';
    updateStrength(pw);
    $('#pwnedBox').classList.remove('show');
  });

  $('#copyPassBtn').addEventListener('click', () =>
    copyText(passInput.value, { autoClear: true })
  );

  passInput.addEventListener('input', () => {
    updateStrength(passInput.value);
    $('#pwnedBox').classList.remove('show');
  });

  $('#checkPwnedBtn').addEventListener('click', () => runPwned(passInput.value));

  $('#saveBtn').addEventListener('click', () => saveDetail(entry));

  const delBtn = $('#deleteBtn');
  if (delBtn) {
    delBtn.addEventListener('click', () => deleteEntry(entry.id));
  }
}

async function saveDetail(entry) {
  const name = $('#fName').value.trim();
  if (!name) {
    toast('Dá um nome à entrada');
    $('#fName').focus();
    return;
  }
  const data = {
    name,
    url: $('#fUrl').value.trim(),
    username: $('#fUser').value.trim(),
    password: $('#fPass').value,
    notes: $('#fNotes').value,
    updatedAt: Date.now()
  };

  if (state.isNew) {
    const newEntry = { id: crypto.randomUUID(), pwnedCount: 0, ...data };
    state.vault.entries.push(newEntry);
    state.selectedId = newEntry.id;
    state.isNew = false;
  } else {
    Object.assign(entry, data);
    state.selectedId = entry.id;
  }

  await saveVault();
  toast('Guardado');
  renderList();
  selectEntry(state.selectedId);
}

async function deleteEntry(id) {
  if (!confirm('Eliminar esta entrada? Não há volta a dar.')) return;
  state.vault.entries = state.vault.entries.filter((e) => e.id !== id);
  state.selectedId = null;
  await saveVault();
  toast('Eliminada');
  renderList();
  renderEmpty();
}

/* ---------------- força + pwned ---------------- */

function updateStrength(pw) {
  const fill = $('#strengthFill');
  const label = $('#strengthLabel');
  if (!fill) return;
  const r = estimateStrength(pw);
  fill.className = 'strength-fill s' + (r.score || 0);
  fill.style.width = (r.score / 4) * 100 + '%';
  if (!pw) {
    label.innerHTML = '—';
  } else {
    label.innerHTML = `<b>${r.label}</b> · ${r.entropy} bits`;
  }
}

async function runPwned(pw) {
  const box = $('#pwnedBox');
  if (!pw) {
    toast('Não há password para verificar');
    return;
  }
  box.classList.add('show');
  box.innerHTML = '<div class="pwned-status" style="color:var(--muted)">A verificar contra a base de fugas…</div>';

  try {
    const r = await checkPwned(pw);

    // marca a entrada selecionada (se aplicável)
    if (state.selectedId) {
      const ent = state.vault.entries.find((e) => e.id === state.selectedId);
      if (ent) { ent.pwnedCount = r.count; await saveVault(); renderList(); }
    }

    const statusHtml = r.pwned
      ? `<div class="pwned-status bad">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
           Encontrada em fugas de dados
           <span class="count">${r.count.toLocaleString('pt')}×</span>
         </div>`
      : `<div class="pwned-status safe">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>
           Não aparece em nenhuma fuga conhecida
           <span class="count">0×</span>
         </div>`;

    box.innerHTML = statusHtml + `
      <div class="kanon">
        <div class="kanon-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
          k-anonymity — o que saiu da tua máquina
        </div>
        <div class="hash-line">
          SHA-1:
          <span class="hash-sent">${r.prefix}</span><span class="hash-kept">${r.suffix}</span>
        </div>
        <div class="kanon-note">
          Só os 5 primeiros caracteres (a verde) foram enviados à API. O resto do hash —
          e a password — nunca saíram daqui. A resposta traz centenas de hashes e a
          comparação é feita localmente.
        </div>
      </div>`;
  } catch (e) {
    box.innerHTML = `<div class="pwned-status bad">Erro: ${escapeHtml(e.message)}</div>`;
  }
}

/* ---------------- gerador (modal) ---------------- */

function genOptions() {
  return {
    length: parseInt($('#genLength').value, 10),
    upper: $('#genUpper').checked,
    lower: $('#genLower').checked,
    digits: $('#genDigits').checked,
    symbols: $('#genSymbols').checked,
    excludeAmbiguous: $('#genAmbig').checked
  };
}

function rollGen() {
  const pw = generatePassword(genOptions());
  $('#genResult').value = pw || '(escolhe pelo menos um tipo)';
}

function openGen() {
  $('#genModal').classList.add('show');
  rollGen();
}

function bindGenerator() {
  $('#genBtn').addEventListener('click', openGen);
  $('#genCloseBtn').addEventListener('click', () => $('#genModal').classList.remove('show'));
  $('#genModal').addEventListener('click', (e) => {
    if (e.target === $('#genModal')) $('#genModal').classList.remove('show');
  });
  $('#genRerollBtn').addEventListener('click', rollGen);
  $('#genCopyBtn').addEventListener('click', () => copyText($('#genResult').value, { autoClear: true }));
  $('#genLength').addEventListener('input', () => {
    $('#genLengthOut').textContent = $('#genLength').value;
    rollGen();
  });
  ['genUpper', 'genLower', 'genDigits', 'genSymbols', 'genAmbig'].forEach((id) =>
    $('#' + id).addEventListener('change', rollGen)
  );
}

/* ---------------- menu de opções ---------------- */

function toggleMenu(force) {
  const pop = $('#menuPopover');
  const show = force !== undefined ? force : !pop.classList.contains('show');
  pop.classList.toggle('show', show);
}

function bindMenu() {
  $('#menuBtn').addEventListener('click', (e) => { e.stopPropagation(); toggleMenu(); });
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.menu-wrap')) toggleMenu(false);
  });
  $('#checkAllBtn').addEventListener('click', () => { toggleMenu(false); checkAll(); });
  $('#exportBtn').addEventListener('click', () => { toggleMenu(false); exportVault(); });
  $('#importBtn').addEventListener('click', () => { toggleMenu(false); $('#importInput').click(); });
  $('#importInput').addEventListener('change', importVault);
}

/* ---------------- exportar / importar ---------------- */

async function exportVault() {
  // exporta o blob CIFRADO (seguro de guardar como backup)
  const blob = await encryptVault(state.vault, state.master);
  const stamp = new Date().toISOString().slice(0, 10);
  const file = new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(file);
  const a = document.createElement('a');
  a.href = url;
  a.download = `keyvault-backup-${stamp}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Cofre exportado (cifrado)');
}

async function importVault(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = ''; // permite reimportar o mesmo ficheiro
  if (!file) return;

  let blob;
  try {
    blob = JSON.parse(await file.text());
  } catch {
    toast('Ficheiro inválido');
    return;
  }
  if (!blob.ciphertext || !blob.salt || !blob.iv) {
    toast('Não parece um cofre KeyVault');
    return;
  }
  if (!confirm(
    'Importar substitui o cofre atual desta máquina.\n\n' +
    'Vais precisar da master password correspondente a este ficheiro para o abrir. Continuar?'
  )) return;

  try {
    await Storage.save(blob);
    toast('Cofre importado — desbloqueia com a respetiva password');
    lock();
  } catch {
    toast('Erro ao importar');
  }
}

/* ---------------- verificar todas ---------------- */

async function checkAll() {
  const entries = state.vault.entries.filter((e) => e.password);
  if (entries.length === 0) { toast('Não há passwords para verificar'); return; }

  const bar = $('#bulkBar');
  bar.classList.add('show');
  $('#bulkFill').style.width = '0%';

  // não repetir chamadas para passwords iguais
  const cache = new Map();
  let exposed = 0;
  let done = 0;

  for (const entry of entries) {
    $('#bulkText').textContent = `A verificar ${done + 1}/${entries.length}`;
    try {
      let count;
      if (cache.has(entry.password)) {
        count = cache.get(entry.password);
      } else {
        const r = await checkPwned(entry.password);
        count = r.count;
        cache.set(entry.password, count);
        await new Promise((res) => setTimeout(res, 120)); // simpático com a API
      }
      entry.pwnedCount = count;
      if (count > 0) exposed++;
    } catch {
      // ignora falhas pontuais, continua
    }
    done++;
    $('#bulkFill').style.width = (done / entries.length) * 100 + '%';
  }

  await saveVault();
  renderList();
  if (state.selectedId) selectEntry(state.selectedId);

  setTimeout(() => bar.classList.remove('show'), 600);
  toast(exposed > 0
    ? `${exposed} de ${entries.length} expostas em fugas`
    : `Nenhuma das ${entries.length} aparece em fugas`);
}

/* ---------------- wiring global ---------------- */

$('#unlockBtn').addEventListener('click', handleUnlock);
$('#masterInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleUnlock(); });
$('#confirmInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleUnlock(); });
$('#lockBtn').addEventListener('click', lock);
$('#addBtn').addEventListener('click', newEntry);
$('#searchInput').addEventListener('input', (e) => { state.search = e.target.value; renderList(); });
bindGenerator();
bindMenu();

init();
