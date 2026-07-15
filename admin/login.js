const form = document.getElementById('login-form');
const username = document.getElementById('username');
const password = document.getElementById('password');
const statusNode = document.getElementById('login-status');
const submitButton = document.getElementById('login-submit');
const tokenStorageKey = 'payloader-admin-access-token';
const jwtPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

const setStatus = (message, tone = '') => {
  statusNode.textContent = message;
  statusNode.dataset.tone = tone;
};

const setBusy = busy => {
  submitButton.disabled = busy;
  submitButton.textContent = busy ? '登录中' : '登录';
};

form.addEventListener('submit', async event => {
  event.preventDefault();
  const payload = {
    username: username.value.trim(),
    password: password.value,
  };

  if (!payload.username || !payload.password) {
    setStatus('请输入账号和密码', 'error');
    return;
  }

  setBusy(true);
  setStatus('');
  try {
    const response = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `登录失败：HTTP ${response.status}`);
    }
    if (body.tokenType !== 'Bearer' || !jwtPattern.test(String(body.accessToken || ''))) {
      throw new Error('服务器返回的管理员令牌格式无效');
    }
    sessionStorage.setItem(tokenStorageKey, body.accessToken);
    window.location.replace('/admin');
  } catch (error) {
    password.value = '';
    password.focus();
    setStatus(error instanceof Error ? error.message : '登录失败，请稍后重试', 'error');
  } finally {
    setBusy(false);
  }
});

const restoreExistingSession = async () => {
  const token = sessionStorage.getItem(tokenStorageKey) || '';
  if (!jwtPattern.test(token)) {
    sessionStorage.removeItem(tokenStorageKey);
    return;
  }
  try {
    const response = await fetch('/api/admin/session', {
      headers: { authorization: `Bearer ${token}` },
    });
    if (response.ok) {
      window.location.replace('/admin');
      return;
    }
  } catch {
    // Keep the login form usable when the session probe is unavailable.
  }
  sessionStorage.removeItem(tokenStorageKey);
};

restoreExistingSession();
