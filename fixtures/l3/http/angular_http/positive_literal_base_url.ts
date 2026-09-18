// Static fixture: a base URL written as one string literal.
const baseUrl = '/api';

export function list(client: HttpClient) {
  return client.get('/items');
}
