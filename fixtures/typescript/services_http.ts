// Component-local Angular HTTP fixture for
// graph_analyze::l3::angular_http (task F-005). A literal route with a literal
// verb is supported; a template-literal route, a computed route, a non-literal
// verb and a call on a receiver that is not an HTTP client must be reported as
// unresolved instead of guessed. The machine-readable half is
// services_http.expected.json.

import { HttpClient } from '@angular/common/http';

export class ItemsService {
  private readonly baseUrl = '/api';

  constructor(private http: HttpClient) {}

  list() {
    return this.http.get<Item[]>('/api/items');
  }

  create(item: Item) {
    return this.http.post('/api/items', item);
  }

  health() {
    return this.http.get('https://cdn.example.com/health');
  }

  put() {
    return this.http.request('PUT', '/api/items/1', body);
  }

  remove(id: string) {
    return this.http.delete(`/api/items/${id}`);
  }

  dynamic(id: string) {
    return this.http.get(this.urlFor(id));
  }

  custom() {
    return this.http.request(verb, '/api/items/1');
  }

  notHttp() {
    return map.get('/x');
  }
}
