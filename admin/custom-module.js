document.addEventListener('DOMContentLoaded', () => {
  const workspace = document.querySelector('.workspace');
  let panel = null;
  let editingId = null;
  let editingDestination = null;
  let messageTimer = null;
  let recordByKey = new Map();

  const recordKey = (id, destination) => `${destination}:${id}`;

  const tokenStorageKey = 'payloader-admin-access-token';
  const getAccessToken = () => sessionStorage.getItem(tokenStorageKey) || '';
  const authorizedHeaders = (headers = {}) => {
    const token = getAccessToken();
    return token ? { ...headers, authorization: `Bearer ${token}` } : headers;
  };
  const authorizedFetch = async (url, options = {}) => {
    const response = await fetch(url, {
      ...options,
      headers: authorizedHeaders(options.headers),
    });
    if (response.status === 401) {
      sessionStorage.removeItem(tokenStorageKey);
      window.location.replace('/admin/login');
      throw new Error('会话已过期，请重新登录');
    }
    return response;
  };

  const buildPanel = () => {
    const element = document.createElement('section');
    element.className = 'custom-payload-workspace hidden';
    element.setAttribute('aria-label', '自定义内容管理');
    element.innerHTML = `
      <form id="cp-form">
        <div class="cp-form-heading">
          <span class="section-kicker">自定义内容</span>
          <h3 id="cp-title-h">新增自定义内容</h3>
        </div>
        <fieldset class="cp-field cp-destination-field">
          <legend>添加到</legend>
          <div class="cp-segmented" id="cp-destination">
            <label>
              <input type="radio" name="cp-destination" value="payloads" checked />
              <span>Payload</span>
            </label>
            <label>
              <input type="radio" name="cp-destination" value="tools" />
              <span>工具命令</span>
            </label>
          </div>
        </fieldset>
        <label class="cp-field" for="cp-name">
          <span>标题</span>
          <input id="cp-name" class="cp-input" type="text" placeholder="例如：SQL 注入速查表" />
        </label>
        <label class="cp-field cp-content-field" for="cp-content">
          <span>内容</span>
          <small>支持多行纯文本</small>
          <textarea id="cp-content" class="cp-input" placeholder="粘贴或编写内容"></textarea>
        </label>
        <div id="cp-btns">
          <button class="btn primary" id="cp-save" type="submit">保存</button>
          <button class="btn hidden" id="cp-cancel" type="button">取消编辑</button>
        </div>
        <div class="cp-message hidden" id="cp-msg" role="status" aria-live="polite"></div>
      </form>
      <section id="cp-list-panel" aria-labelledby="cp-list-title">
        <header class="cp-list-header">
          <div>
            <span class="section-kicker">内容列表</span>
            <h3 id="cp-list-title">已添加内容</h3>
          </div>
          <span class="count-badge" id="cp-count">加载中</span>
        </header>
        <div id="cp-list"></div>
      </section>
    `;
    return element;
  };

  const showMessage = (message, success) => {
    const element = document.getElementById('cp-msg');
    clearTimeout(messageTimer);
    element.textContent = message;
    element.className = `cp-message ${success ? 'success' : 'error'}`;
    messageTimer = setTimeout(() => element.classList.add('hidden'), 4000);
  };

  const selectedDestination = () => (
    panel?.querySelector('input[name="cp-destination"]:checked')?.value === 'tools' ? 'tools' : 'payloads'
  );

  const setDestination = destination => {
    const value = destination === 'tools' ? 'tools' : 'payloads';
    const input = panel?.querySelector(`input[name="cp-destination"][value="${value}"]`);
    if (input instanceof HTMLInputElement) input.checked = true;
  };

  const responseError = async response => {
    const body = await response.json().catch(() => null);
    return String(body?.error || `HTTP ${response.status}`);
  };

  const cancelEdit = () => {
    editingId = null;
    editingDestination = null;
    document.getElementById('cp-name').value = '';
    document.getElementById('cp-content').value = '';
    setDestination('payloads');
    document.getElementById('cp-title-h').textContent = '新增自定义内容';
    document.getElementById('cp-cancel').classList.add('hidden');
  };

  const startEdit = record => {
    editingId = record.id;
    editingDestination = record.destination;
    document.getElementById('cp-name').value = record.title;
    document.getElementById('cp-content').value = record.content;
    setDestination(record.destination);
    document.getElementById('cp-title-h').textContent = `编辑：${record.title}`;
    document.getElementById('cp-cancel').classList.remove('hidden');
    document.getElementById('cp-name').focus();
  };

  const loadList = async () => {
    try {
      const response = await authorizedFetch('/api/admin/custom-content');
      if (!response.ok) throw new Error(await responseError(response));
      const data = await response.json();
      const records = Array.isArray(data.items) ? data.items : [];
      recordByKey = new Map(records.map(record => [recordKey(record.id, record.destination), record]));
      const countElement = document.getElementById('cp-count');
      const listElement = document.getElementById('cp-list');
      countElement.textContent = `${records.length} 条`;

      if (!records.length) {
        const empty = document.createElement('div');
        empty.className = 'cp-empty';
        empty.innerHTML = '<strong>暂无自定义内容</strong><span>使用左侧表单创建第一条记录。</span>';
        listElement.replaceChildren(empty);
        return;
      }

      const fragment = document.createDocumentFragment();
      for (const record of records) {
        const key = recordKey(record.id, record.destination);
        const titleText = String(record.title || '未命名');
        const content = String(record.content || '');
        const card = document.createElement('article');
        card.className = 'cp-card';

        const info = document.createElement('div');
        info.className = 'cp-card-info';
        const badge = document.createElement('span');
        badge.className = `cp-destination-badge ${record.destination === 'tools' ? 'tools' : 'payloads'}`;
        badge.textContent = record.destination === 'tools' ? '工具命令' : 'Payload';
        const title = document.createElement('h4');
        title.textContent = titleText;
        const preview = document.createElement('p');
        preview.textContent = `${content.slice(0, 120).replace(/\n/g, ' ')}${content.length > 120 ? '…' : ''}`;
        info.append(badge, title, preview);

        const actions = document.createElement('div');
        actions.className = 'cp-card-actions';
        const edit = document.createElement('button');
        edit.className = 'btn';
        edit.type = 'button';
        edit.textContent = '编辑';
        edit.dataset.action = 'edit';
        edit.dataset.recordKey = key;
        const remove = document.createElement('button');
        remove.className = 'btn danger-soft';
        remove.type = 'button';
        remove.textContent = '删除';
        remove.dataset.action = 'delete';
        remove.dataset.recordKey = key;
        actions.append(edit, remove);
        card.append(info, actions);
        fragment.append(card);
      }
      listElement.replaceChildren(fragment);
    } catch (error) {
      showMessage(`加载失败：${error instanceof Error ? error.message : String(error)}`, false);
    }
  };

  const save = async () => {
    const name = document.getElementById('cp-name').value.trim();
    const content = document.getElementById('cp-content').value.trim();
    if (!name || !content) {
      showMessage('请填写标题和内容', false);
      return;
    }
    const accessToken = getAccessToken();
    if (!accessToken) {
      showMessage('会话已过期，请重新登录', false);
      return;
    }

    const button = document.getElementById('cp-save');
    button.disabled = true;
    button.textContent = '保存中';
    try {
      const destination = selectedDestination();
      const url = editingId
        ? `/api/admin/custom-content/${encodeURIComponent(editingId)}`
        : '/api/admin/custom-content';
      const response = await authorizedFetch(url, {
        method: editingId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: name,
          content,
          destination,
          ...(editingDestination ? { sourceDestination: editingDestination } : {}),
        }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      showMessage(editingId ? '修改成功' : '保存成功', true);
      cancelEdit();
      await loadList();
    } catch (error) {
      showMessage(`保存失败：${error instanceof Error ? error.message : String(error)}`, false);
    } finally {
      button.disabled = false;
      button.textContent = '保存';
    }
  };

  const remove = async record => {
    const accessToken = getAccessToken();
    if (!accessToken) {
      showMessage('会话已过期，请重新登录', false);
      return;
    }
    if (!confirm('确认删除这条自定义内容？')) return;
    try {
      const response = await authorizedFetch(`/api/admin/custom-content/${encodeURIComponent(record.id)}?destination=${encodeURIComponent(record.destination)}`, {
        method: 'DELETE',
      });
      if (!response.ok) throw new Error(await responseError(response));
      if (editingId === record.id && editingDestination === record.destination) cancelEdit();
      showMessage('已删除', true);
      await loadList();
    } catch (error) {
      showMessage(`删除失败：${error instanceof Error ? error.message : String(error)}`, false);
    }
  };

  const showCustom = () => {
    if (!panel) {
      panel = buildPanel();
      workspace.insertAdjacentElement('afterend', panel);
      panel.querySelector('#cp-form').addEventListener('submit', event => {
        event.preventDefault();
        save();
      });
      panel.querySelector('#cp-cancel').addEventListener('click', cancelEdit);
      panel.addEventListener('click', event => {
        const action = event.target instanceof Element ? event.target.closest('button[data-action][data-record-key]') : null;
        if (!(action instanceof HTMLButtonElement)) return;
        const record = recordByKey.get(action.dataset.recordKey || '');
        if (!record) return;
        if (action.dataset.action === 'delete') remove(record);
        if (action.dataset.action === 'edit') startEdit(record);
      });
    }
    document.body.dataset.module = 'custom';
    workspace.classList.add('hidden');
    panel.classList.remove('hidden');
    document.getElementById('module-title').textContent = '自定义内容';
    const moduleDescription = document.getElementById('module-desc');
    if (moduleDescription) {
      moduleDescription.textContent = '';
      moduleDescription.hidden = true;
    }
    document.getElementById('admin-module-select').value = 'custom';
    loadList();
  };

  const hideCustom = () => {
    panel?.classList.add('hidden');
    workspace.classList.remove('hidden');
  };

  document.addEventListener('click', event => {
    const button = event.target instanceof Element ? event.target.closest('.module-btn') : null;
    if (!button) return;
    if (button.dataset.module === 'custom') {
      event.stopImmediatePropagation();
      document.querySelectorAll('.module-btn').forEach(moduleButton => moduleButton.classList.toggle('active', moduleButton === button));
      showCustom();
    } else {
      hideCustom();
    }
  }, true);
});
