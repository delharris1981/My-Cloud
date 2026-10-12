// RFC 6238 TOTP (+ RFC 4648 base32) implemented with Node crypto — no external
// TOTP dependency. Compatible with Google Authenticator, Authy, 1Password, etc.
import crypto from 'crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

export function generateSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160-bit
}

function hotp(secret, counter) {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(bin % 1e6).padStart(6, '0');
}

// Verify a code, allowing +/- 1 step for clock skew. Uses timing-safe compare.
export function verifyTotp(secret, code, nowMs = Date.now()) {
  const clean = String(code || '').replace(/\D/g, '');
  if (clean.length !== 6) return false;
  const step = Math.floor(nowMs / 1000 / 30);
  for (let w = -1; w <= 1; w++) {
    const expected = hotp(secret, step + w);
    const a = Buffer.from(expected), b = Buffer.from(clean);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

export function otpauthUri(secret, label, issuer) {
  const l = encodeURIComponent(issuer) + ':' + encodeURIComponent(label);
  return `otpauth://totp/${l}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
