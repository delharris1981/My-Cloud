// Per-key async mutex. Used to serialize quota-affecting writes per user so
// concurrent uploads/copies/restores can't each see the full free quota and
// collectively blow past it.
const chains = new Map();

export function withLock(key, fn) {
  const prev = chains.get(key) || Promise.resolve();
  const result = prev.then(fn, fn); // run fn once prev settles, success or not
  const tail = result.then(() => {}, () => {});
  chains.set(key, tail);
  tail.finally(() => {
    // Drop the entry once this is the last op in the chain, to avoid growth.
    if (chains.get(key) === tail) chains.delete(key);
  });
  return result;
}
