// Typed fetch wrapper for the JSON API. M1 adds auth endpoints here.
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    throw new ApiError(res.status, await res.text());
  }
  return (await res.json()) as T;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, body: string) {
    super(`API ${status}: ${body}`);
    this.status = status;
  }
}
