// Static fixture: the receiver is a collection, not an HTTP client.
export function read(cache: Map<string, string>, key: string) {
  return cache.get(key);
}
