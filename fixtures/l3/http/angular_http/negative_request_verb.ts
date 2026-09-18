// Static fixture: `request(` carries no literal verb, and a literal verb with a
// computed route still may not become a call.
export function send(http: HttpClient, verb: string, url: string, body: unknown) {
  return http.request(verb, '/api/items');
}

export function sendAgain(http: HttpClient, url: string, body: unknown) {
  return http.request('POST', url, body);
}
