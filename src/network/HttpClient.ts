export interface HttpRequest {
  url: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  headers?: Record<string, string>;
  body?: unknown;
}

export interface HttpClient {
  request<T = unknown>(input: HttpRequest): Promise<T>;
}

export class FetchHttpClient implements HttpClient {
  async request<T = unknown>(input: HttpRequest): Promise<T> {
    const fetchFn = (globalThis as unknown as { fetch?: typeof fetch }).fetch;
    if (!fetchFn) {
      throw new Error("A fetch-compatible HTTP client is required.");
    }

    const response = await fetchFn(input.url, {
      method: input.method ?? "GET",
      headers: {
        "content-type": "application/json",
        ...(input.headers ?? {})
      },
      body: input.body === undefined ? undefined : JSON.stringify(input.body)
    });

    if (!response.ok) {
      throw new Error(`HTTP request failed with status ${response.status}.`);
    }

    return (await response.json()) as T;
  }
}
