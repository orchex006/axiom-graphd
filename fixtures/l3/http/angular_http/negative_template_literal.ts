// Static fixture: the route is a template literal and must not become a call.
export function load(http: HttpClient, id: string) {
  return http.get(`/api/items/${id}`);
}
