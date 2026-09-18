// Static fixture: the route is a computed expression, not a literal.
export function load(http: HttpClient, id: string) {
  return http.get(urlFor(id));
}
