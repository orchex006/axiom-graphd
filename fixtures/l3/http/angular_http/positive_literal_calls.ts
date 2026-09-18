// Static fixture: literal Angular HttpClient calls the adapter must analyse.
// Source text only; nothing here is executed and no runtime log is involved.
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable()
export class ItemsService {
  private readonly baseUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  list() {
    return this.http.get<Item[]>('/api/items');
  }

  create(item: Item) {
    return this.http.post('/api/items', item);
  }

  replace(item: Item) {
    return this.http.request('PUT', '/api/items/1', item);
  }

  health() {
    return this.http.get('https://cdn.example.com/health');
  }
}
