// Generates a realistic legacy /config using the Node app's own modules, so the
// Go migration is tested against data the real app would have written — not
// against fixtures this repo invented.
//
// The Node app is archived under OLD/ and is kept as the rollback target, so
// its TOTP generator is imported from there.
//
// Run: node dev-config-gen.js <configDir>
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { generateSecret } from './OLD/server/totp.js';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: node dev-config-gen.js <configDir>');
  process.exit(1);
}
fs.mkdirSync(dir, { recursive: true });

// secret.key exactly as config.js writes it: 48 random bytes, hex.
const secret = [...crypto.getRandomValues(new Uint8Array(48))]
  .map(b => b.toString(16).padStart(2, '0')).join('');
fs.writeFileSync(path.join(dir, 'secret.key'), secret);

fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({
  siteName: 'Home Cloud',
  allowSignup: false,
  defaultQuotaMB: 0,
  sessionDays: 30,
  trashRetentionDays: 30,
  allowPublicShares: true
}, null, 2));

const now = Date.now();
const totpSecret = generateSecret();
const recovery = [];
const shownRecovery = [];
for (let i = 0; i < 10; i++) {
  const c = crypto.getRandomValues(new Uint8Array(5))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  shownRecovery.push(c);
  recovery.push(bcrypt.hashSync(c, 10));
}

const appPwToken = crypto.getRandomValues(new Uint8Array(15))
  .map((b, i) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[b % 64])
  .join('');

const users = [
  {
    username: 'admin',
    passwordHash: bcrypt.hashSync('correct horse battery staple', 10),
    isAdmin: true,
    quotaMB: 0,
    createdAt: now - 86400000 * 30,
    passwordChangedAt: now - 86400000 * 20,
    totpSecret,
    recovery,
    appPasswords: [{
      id: crypto.getRandomValues(new Uint8Array(4)).map(b => b.toString(16).padStart(2, '0')).join(''),
      label: 'Finder',
      hash: bcrypt.hashSync(appPwToken, 10),
      createdAt: now - 86400000 * 5
    }]
  },
  {
    username: 'family',
    passwordHash: bcrypt.hashSync('hunter2', 10),
    isAdmin: false,
    quotaMB: 512,
    createdAt: now - 86400000 * 10,
    passwordChangedAt: now - 86400000 * 10
  },
  // Unlimited quota expressed the way the Node version writes it: 0.
  {
    username: 'guest',
    passwordHash: bcrypt.hashSync('guestpass', 10),
    isAdmin: false,
    quotaMB: 0,
    createdAt: now - 86400000,
    passwordChangedAt: now - 86400000
  }
];
fs.writeFileSync(path.join(dir, 'users.json'), JSON.stringify({ users }, null, 2));

const shareExpiry = now + 86400000 * 7;
const shares = [
  {
    token: 'single-file-share-token',
    owner: 'family',
    passwordHash: bcrypt.hashSync('sharepass', 10),
    expiresAt: shareExpiry,
    createdAt: now - 86400000,
    downloads: 3,
    path: 'holiday/photos.zip',
    isDir: false,
    allowUpload: false
  },
  {
    token: 'multi-item-share-token',
    owner: 'admin',
    passwordHash: null,
    expiresAt: null,
    createdAt: now - 3600000,
    downloads: 0,
    isMulti: true,
    items: ['report.pdf', 'notes', 'notes/todo.md'],
    isDir: true,
    allowUpload: false
  },
  {
    token: 'dropbox-share-token',
    owner: 'family',
    passwordHash: null,
    expiresAt: null,
    createdAt: now - 7200000,
    downloads: 12,
    path: 'inbox',
    isDir: true,
    allowUpload: true
  }
];
fs.writeFileSync(path.join(dir, 'shares.json'), JSON.stringify({ shares }, null, 2));

// Emitted so the Go-side test can assert the sealed values decrypt back to
// exactly these, and that bcrypt hashes still verify.
console.log(JSON.stringify({
  secret,
  totpSecret,
  recoveryShown: shownRecovery,
  appPwToken,
  passwords: { admin: 'correct horse battery staple', family: 'hunter2', guest: 'guestpass' },
  sharePassword: 'sharepass',
  shareExpiry
}, null, 2));