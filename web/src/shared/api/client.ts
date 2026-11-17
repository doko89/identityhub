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

// errorMessage pulls the user-facing {error} string out of a failed
// response, falling back when the body is not JSON.
export async function errorMessage(res: Response, fallback: string): Promise<string> {
  const data = (await res.json().catch(() => null)) as { error?: string } | null;
  return data?.error ?? fallback;
}
