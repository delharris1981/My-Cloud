import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const CONFIG_DIR = process.env.MYCLOUD_CONFIG_DIR || '/config';
const DATA_DIR = process.env.MYCLOUD_DATA_DIR || '/data';
const PORT = parseInt(process.env.MYCLOUD_PORT || '8686', 10);

fs.mkdirSync(CONFIG_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, 'users'), { recursive: true });

// Session-signing secret persists across restarts so logins survive updates.
const secretFile = path.join(CONFIG_DIR, 'secret.key');
function writeSecretAtomically(value) {
  const tmp = secretFile + '.tmp';
  const fd = fs.openSync(tmp, 'w', 0o600);
  fs.writeSync(fd, value);
  fs.fsyncSync(fd); // flush before rename so a crash can't leave a partial key
  fs.closeSync(fd);
  fs.renameSync(tmp, secretFile);
}
let secret = fs.existsSync(secretFile) ? fs.readFileSync(secretFile, 'utf8').trim() : '';
// Regenerate if missing, empty, or suspiciously short (e.g. a truncated write
// from an interrupted first boot) — an empty key would make tokens forgeable.
if (secret.length < 32) {
  secret = crypto.randomBytes(48).toString('hex');
  writeSecretAtomically(secret);
}

const settingsFile = path.join(CONFIG_DIR, 'settings.json');
const defaultSettings = {
  siteName: 'My Cloud',
  allowSignup: false,
  defaultQuotaMB: 0, // 0 = unlimited
  sessionDays: 30,
  trashRetentionDays: 30,
  allowPublicShares: true // admin can turn off public share links entirely
};
let settings = { ...defaultSettings };
if (fs.existsSync(settingsFile)) {
  try {
    settings = { ...defaultSettings, ...JSON.parse(fs.readFileSync(settingsFile, 'utf8')) };
  } catch {
    // Corrupt settings fall back to defaults rather than crashing the server.
  }
} else {
  fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
}

export function saveSettings(patch) {
  settings = { ...settings, ...patch };
  // Atomic write so a crash mid-save can't corrupt settings.json (which would
  // silently reset the site name/quota/retention to defaults on next boot).
  const tmp = settingsFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(settings, null, 2));
  fs.renameSync(tmp, settingsFile);
  return settings;
}

export { CONFIG_DIR, DATA_DIR, PORT, secret, settings };
