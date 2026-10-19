const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal: true});
export const KDF_ITERATIONS = 600000;
const aad = context => encoder.encode('personal-schedule/v1/' + context);
export function encode64(value) {
  const bytes = new Uint8Array(value);
  let text = '';
  for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(text);
}
export function decode64(text) {
  if (typeof text !== 'string' || text.length > 4000000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw Error('Invalid encrypted data');
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}
export function checkEnvelope(value) {
  if (!value || ![1, 2].includes(value.version) || value.kdf !== 'PBKDF2-SHA256' || value.cipher !== 'AES-256-GCM') throw Error('Unsupported encrypted data');
  if (!Number.isInteger(value.iterations) || value.iterations < KDF_ITERATIONS || value.iterations > 2000000) throw Error('Unsupported key derivation');
  if (decode64(value.salt).length !== 16) throw Error('Invalid encryption salt');
  if (value.version === 2 && (!value.wrappedKey || decode64(value.wrappedKey.iv).length !== 12)) throw Error('Invalid encrypted key');
  return value;
}
export async function deriveKey(passphrase, salt, iterations = KDF_ITERATIONS) {
  if (typeof passphrase !== 'string' || !passphrase || passphrase.length > 1024) throw Error('Invalid unlock code');
  checkEnvelope({version: 1, kdf: 'PBKDF2-SHA256', cipher: 'AES-256-GCM', salt, iterations});
  const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt: decode64(salt), iterations}, material, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
}
export async function encryptJSON(value, key, context = 'dataset') {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const content = encoder.encode(JSON.stringify(value));
  if (content.byteLength > 2000000) throw Error('Schedule data is too large');
  const encrypted = await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: aad(context), tagLength: 128}, key, content);
  return {iv: encode64(iv), ciphertext: encode64(encrypted)};
}
export async function decryptJSON(box, key, context = 'dataset') {
  if (!box || decode64(box.iv).length !== 12) throw Error('Invalid encryption nonce');
  const bytes = await crypto.subtle.decrypt({name: 'AES-GCM', iv: decode64(box.iv), additionalData: aad(context), tagLength: 128}, key, decode64(box.ciphertext));
  return JSON.parse(decoder.decode(bytes));
}
async function importDataKey(raw) {
  const bytes = decode64(raw);
  if (bytes.length !== 32) throw Error('Invalid schedule key');
  return crypto.subtle.importKey('raw', bytes, {name: 'AES-GCM'}, false, ['encrypt', 'decrypt']);
}
export async function encryptDataset(data, passphrase, salt, rawDataKey = null) {
  const unlockKey = await deriveKey(passphrase, salt);
  if (rawDataKey) {
    const key = await importDataKey(rawDataKey);
    return {version: 2, kdf: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, salt, cipher: 'AES-256-GCM', wrappedKey: await encryptJSON({key: rawDataKey}, unlockKey, 'schedule-key'), ...await encryptJSON(data, key)};
  }
  return {version: 1, kdf: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, salt, cipher: 'AES-256-GCM', ...await encryptJSON(data, unlockKey)};
}
export async function unlockDataset(envelope, passphrase) {
  checkEnvelope(envelope);
  const unlockKey = await deriveKey(passphrase, envelope.salt, envelope.iterations);
  const key = envelope.version === 2 ? await importDataKey((await decryptJSON(envelope.wrappedKey, unlockKey, 'schedule-key')).key) : unlockKey;
  return {key, salt: envelope.salt, iterations: envelope.iterations, dataset: await decryptJSON(envelope, key)};
}
export async function fetchEnvelope() {
  const response = await fetch('./data.enc.json', {cache: 'no-store', credentials: 'omit'});
  if (!response.ok) throw Error('无法读取加密日程，请稍后重试。');
  return checkEnvelope(await response.json());
}
export async function readPublished(session) {
  const envelope = await fetchEnvelope();
  if (envelope.salt !== session.salt || envelope.iterations !== session.iterations) throw Error('解锁设置已更新，请重新打开网页并输入新口令。');
  return decryptJSON(envelope, session.key);
}
export function storageKey() {
  return 'personal-schedule-vault-v1:' + new URL('.', location.href).pathname;
}
export async function readLocal(session) {
  const raw = localStorage.getItem(storageKey());
  return raw ? decryptJSON(JSON.parse(raw), session.key, 'browser-state') : null;
}
export async function writeLocal(session, data) {
  localStorage.setItem(storageKey(), JSON.stringify(await encryptJSON(data, session.key, 'browser-state')));
}
