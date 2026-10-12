import fs from 'fs';
import path from 'path';
import { CONFIG_DIR } from './config.js';

// Tiny JSON-file store with atomic writes. This is the whole "database".
export class JsonStore {
  // critical: if true, a corrupt file aborts startup instead of resetting to
  // `initial`. Used for users.json — silently resetting it to {users:[]} would
  // delete every account AND reopen unauthenticated admin setup to the world.
  constructor(name, initial, { critical = false } = {}) {
    this.file = path.join(CONFIG_DIR, name);
    this.tmp = this.file + '.tmp';
    if (fs.existsSync(this.file)) {
      try {
        this.data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      } catch (err) {
        if (critical) {
          throw new Error(
            `Refusing to start: ${this.file} is corrupt (${err.message}). ` +
            `Restore it from a backup or delete it deliberately, then restart.`
          );
        }
        // Non-critical: preserve the corrupt file for recovery, then reset.
        fs.copyFileSync(this.file, this.file + '.corrupt-' + Date.now());
        this.data = structuredClone(initial);
        this.save();
      }
    } else {
      this.data = structuredClone(initial);
      this.save();
    }
  }

  save() {
    // Sync write+rename can't interleave across requests in Node's single
    // thread, so this is atomic without a lock. Counter keeps temps distinct.
    const tmp = this.tmp + '.' + (this._n = (this._n || 0) + 1);
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    fs.renameSync(tmp, this.file);
  }
}
