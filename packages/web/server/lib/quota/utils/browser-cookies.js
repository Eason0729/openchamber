import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { createDecipheriv, pbkdf2Sync } from 'crypto';
import { Database } from 'bun:sqlite';

/**
 * Search browser cookie databases for a named cookie matching a host pattern.
 *
 * Tries Firefox (plaintext), then Chrome/Chromium/Brave/Edge/Electron
 * (value column → encrypted_value via system keyring).
 *
 * @param {RegExp} hostPattern - regex matching the host (e.g. /\.opencode\.ai$/)
 * @param {string} [cookieName='auth'] - cookie name to search for
 * @returns {string|null} cookie value, or null if not found
 */
export const discoverBrowserCookie = (hostPattern, cookieName = 'auth') => {
  const result = findCookieInFirefox(hostPattern, cookieName);
  if (result) return result;
  return findCookieInChrome(hostPattern, cookieName);
};

/* ---------- Firefox ---------- */

const FIREFOX_DIR = path.join(os.homedir(), '.mozilla', 'firefox');
const PROFILES_INI = path.join(FIREFOX_DIR, 'profiles.ini');

const getFirefoxProfiles = () => {
  if (!fs.existsSync(PROFILES_INI)) return [];

  try {
    const profiles = [];
    for (const line of fs.readFileSync(PROFILES_INI, 'utf8').split('\n')) {
      const m = line.trim().match(/^Path=(.+)$/);
      if (m) profiles.push(m[1]);
    }
    return profiles;
  } catch {
    return [];
  }
};

const regexToLike = (pattern) => {
  let s = pattern.source;
  // Remove start anchor ^ and end anchor $
  s = s.replace(/^\^/, '').replace(/\$$/, '');
  // Unescape regex escapes: \. → .
  s = s.replace(/\\(.)/g, '$1');
  // Remove leading dot (regex uses \.domain → LIKE needs domain)
  s = s.replace(/^\./, '');
  return '%' + s;
};

const findCookieInFirefox = (hostPattern, cookieName) => {
  const hostLike = regexToLike(hostPattern);
  for (const profile of getFirefoxProfiles()) {
    const dbPath = path.join(FIREFOX_DIR, profile, 'cookies.sqlite');
    if (!fs.existsSync(dbPath)) continue;

    try {
      const db = new Database(dbPath, { readonly: true });
      const row = db.query(
        'SELECT value FROM moz_cookies WHERE host LIKE ? AND name = ? LIMIT 1'
      ).get(hostLike, cookieName);
      db.close();
      if (row?.value) return row.value;
    } catch {
      continue;
    }
  }
  return null;
};

/* ---------- Chrome/Chromium/Brave/Edge/Electron ---------- */

const findChromeCookiePaths = () => {
  const configDir = path.join(os.homedir(), '.config');
  if (!fs.existsSync(configDir)) return [];

  const paths = [];
  try {
    for (const entry of fs.readdirSync(configDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const browserDir = path.join(configDir, entry.name);
      try {
        for (const sub of fs.readdirSync(browserDir, { withFileTypes: true })) {
          if (!sub.isDirectory()) continue;
          const cookiePath = path.join(browserDir, sub.name, 'Cookies');
          if (fs.existsSync(cookiePath)) paths.push(cookiePath);
        }
      } catch {
        continue;
      }
    }
  } catch {
    // permission errors
  }
  return paths;
};

const getChromeDecryptionKeys = () => {
  const keys = [];

  if (process.platform === 'linux') {
    for (const app of ['chrome', 'chromium']) {
      try {
        const out = execSync(
          `secret-tool lookup application ${app} 2>/dev/null || true`,
          { encoding: 'utf8', timeout: 3000 }
        ).trim();
        if (out) keys.push(out);
      } catch {
        continue;
      }
    }
    // KDE Wallet fallback for Chromium using portal encryption
    for (const [folder, entry] of [['Chrome Keys', 'Chrome Safe Storage'], ['Chromium Keys', 'Chromium Safe Storage']]) {
      try {
        const out = execSync(
          `kwallet-query -r '${entry}' -f '${folder}' kdewallet 2>/dev/null || true`,
          { encoding: 'utf8', timeout: 3000 }
        ).trim();
        if (out) keys.push(out);
      } catch {
        continue;
      }
    }
  }

  if (process.platform === 'darwin') {
    try {
      const out = execSync(
        'security find-generic-password -w -a "Chrome" -s "Chrome Safe Storage" 2>/dev/null || true',
        { encoding: 'utf8', timeout: 3000 }
      ).trim();
      if (out) keys.push(out);
    } catch {
      // not available
    }
  }

  return keys;
};

const decryptChromeCookie = (encryptedValue, keyPassword) => {
  if (!encryptedValue || encryptedValue.length < 18) return null;

  const tag = Buffer.from(encryptedValue).subarray(0, 3).toString('ascii');
  if (tag !== 'v10' && tag !== 'v11') return null;

  const ciphertext = Buffer.from(encryptedValue).subarray(3);
  if (ciphertext.length === 0) return null;

  try {
    // Derive AES key from keyring password using PBKDF2 (Chrome/Chromium convention)
    const key = pbkdf2Sync(keyPassword, Buffer.from('saltysalt'), 1, 16, 'sha1');
    const iv = Buffer.alloc(16, 0x20); // 16 spaces

    const decipher = createDecipheriv('aes-128-cbc', key, iv);
    decipher.setAutoPadding(false);
    const raw = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // Verify and strip PKCS7 padding
    const lastByte = raw[raw.length - 1];
    if (lastByte === 0 || lastByte > 16) return null;
    const valid = raw.subarray(-lastByte).every((b) => b === lastByte);
    if (!valid) return null;

    // Chrome/Chromium prepends 32 bytes of metadata before the actual cookie value.
    // Skip this prefix and the PKCS7 padding.
    const valueEnd = raw.length - lastByte;
    const valueStart = 32;
    if (valueEnd <= valueStart) return null;

    return raw.subarray(valueStart, valueEnd).toString('utf8');
  } catch {
    return null;
  }
};

const findCookieInChrome = (hostPattern, cookieName) => {
  const hostLike = regexToLike(hostPattern);
  const paths = findChromeCookiePaths();
  if (!paths.length) return null;

  let encryptionKeys = null;

  for (const cookiePath of paths) {
    try {
      const db = new Database(cookiePath, { readonly: true });

      // Try plaintext value column first
      const plain = db.query(
        'SELECT value FROM cookies WHERE host_key LIKE ? AND name = ? AND value != "" LIMIT 1'
      ).get(hostLike, cookieName);
      if (plain?.value) {
        db.close();
        return plain.value;
      }

      // Try encrypted_value
      const enc = db.query(
        'SELECT encrypted_value FROM cookies WHERE host_key LIKE ? AND name = ? AND length(encrypted_value) > 0 LIMIT 1'
      ).get(hostLike, cookieName);
      db.close();

      if (enc?.encrypted_value) {
        if (!encryptionKeys) encryptionKeys = getChromeDecryptionKeys();
        for (const keyPassword of encryptionKeys) {
          const decrypted = decryptChromeCookie(enc.encrypted_value, keyPassword);
          if (decrypted) return decrypted;
        }
      }
    } catch {
      continue;
    }
  }
  return null;
};
