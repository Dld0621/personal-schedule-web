import {fetchEnvelope, unlockDataset} from './vault.mjs?v=20261019-encrypted-v2';
export function waitForUnlock() {
  return new Promise(resolve => {
    const form = document.querySelector('#unlock-form');
    const input = document.querySelector('#unlock-code');
    const error = document.querySelector('#unlock-error');
    const button = document.querySelector('#unlock-button');
    if (!globalThis.crypto?.subtle) {
      error.textContent = '请通过 HTTPS，使用新版 Safari 或 Chrome 打开。';
      button.disabled = true;
      return;
    }
    form.addEventListener('submit', async event => {
      event.preventDefault();
      error.textContent = '';
      button.disabled = true;
      button.textContent = '正在解锁…';
      try {
        const envelope = await fetchEnvelope();
        const session = await unlockDataset(envelope, input.value);
        if (!session.dataset || !Array.isArray(session.dataset.events)) throw Error('Invalid schedule');
        input.value = '';
        document.querySelector('#unlock-screen').hidden = true;
        document.querySelector('.app-shell').hidden = false;
        resolve(session);
      } catch {
        input.value = '';
        error.textContent = '口令不正确，或加密日程暂时无法读取。请检查后重试。';
        input.focus();
      } finally {
        button.disabled = false;
        button.textContent = '解锁日程';
      }
    });
  });
}
