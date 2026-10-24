import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * One client of a Streamable HTTP server that holds the GitLab credentials itself:
 * the client authenticates with `token` (sent as `Authorization: Bearer <token>`) and
 * the server calls GitLab with `gitlabToken`, which the client never sees.
 */
export interface AuthTokenEntry {
  readonly name: string;
  readonly token: string;
  readonly gitlabToken: string;
}

export class AuthTokensFileError extends Error {
  readonly filePath: string;

  constructor(filePath: string, reason: string) {
    super(`Cannot load STREAMABLE_HTTP_AUTH_TOKENS_FILE at ${filePath} (${reason})`);
    this.name = "AuthTokensFileError";
    this.filePath = filePath;
  }
}

export function readAuthTokensFile(filePath: string): string {
  return readFileSync(filePath, { encoding: "utf8" });
}

// Same shape check remote authorization applies to header tokens (index.ts validateToken).
const TOKEN_PATTERN = /^[-a-zA-Z0-9_.]{20,}$/;

function requireString(
  filePath: string,
  index: number,
  entry: Record<string, unknown>,
  key: keyof AuthTokenEntry
): string {
  const value = entry[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new AuthTokensFileError(filePath, `entry ${index}: "${key}" must be a non-empty string`);
  }
  return value.trim();
}

/**
 * Parse and validate the tokens file: a JSON array of `{ name, token, gitlabToken }`.
 * Names and client tokens must be unique, and client tokens must not double as a
 * GitLab token of any entry. Error messages name entries by index and field only,
 * never by value.
 */
export function parseAuthTokensFile(filePath: string, content: string): AuthTokenEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new AuthTokensFileError(filePath, "not valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new AuthTokensFileError(filePath, "expected a non-empty JSON array");
  }

  const entries = parsed.map((raw, index): AuthTokenEntry => {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new AuthTokensFileError(filePath, `entry ${index}: expected an object`);
    }
    const entry = raw as Record<string, unknown>;
    const name = requireString(filePath, index, entry, "name");
    const token = requireString(filePath, index, entry, "token");
    const gitlabToken = requireString(filePath, index, entry, "gitlabToken");
    if (!TOKEN_PATTERN.test(token)) {
      throw new AuthTokensFileError(
        filePath,
        `entry ${index}: "token" must be at least 20 characters of [-a-zA-Z0-9_.]`
      );
    }
    if (!TOKEN_PATTERN.test(gitlabToken)) {
      throw new AuthTokensFileError(
        filePath,
        `entry ${index}: "gitlabToken" must be at least 20 characters of [-a-zA-Z0-9_.]`
      );
    }
    return { name, token, gitlabToken };
  });

  const names = new Set<string>();
  const tokens = new Set<string>();
  entries.forEach((entry, index) => {
    if (names.has(entry.name)) {
      throw new AuthTokensFileError(filePath, `entry ${index}: duplicate "name"`);
    }
    if (tokens.has(entry.token)) {
      throw new AuthTokensFileError(filePath, `entry ${index}: duplicate "token"`);
    }
    names.add(entry.name);
    tokens.add(entry.token);
  });
  entries.forEach((entry, index) => {
    if (entries.some(other => other.gitlabToken === entry.token)) {
      throw new AuthTokensFileError(
        filePath,
        `entry ${index}: "token" equals a "gitlabToken" - clients must not hold GitLab credentials`
      );
    }
  });
  return entries;
}

/**
 * Load the tokens file once at startup. Returns undefined when no path is configured.
 */
export function loadAuthTokensFile(
  filePath: string | undefined,
  readFile: (filePath: string) => string = readAuthTokensFile
): AuthTokenEntry[] | undefined {
  const trimmed = filePath?.trim();
  if (!trimmed) {
    return undefined;
  }
  let content: string;
  try {
    content = readFile(trimmed);
  } catch (error: unknown) {
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? String((error as { code: unknown }).code)
        : "EIO";
    throw new AuthTokensFileError(trimmed, code);
  }
  return parseAuthTokensFile(trimmed, content);
}

/** The token of an `Authorization: Bearer <token>` header, if that is what it holds. */
export function bearerToken(authorization: string | undefined): string | undefined {
  // \S+ rather than .+ keeps the match linear (no ReDoS), as elsewhere in the server.
  return /^Bearer\s+(\S+)$/i.exec(authorization ?? "")?.[1];
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

/**
 * Find the entry whose client token equals `provided`. Every entry is compared,
 * on fixed-length digests, so neither the position of the match nor the length
 * of a token shows in the timing.
 */
export function findAuthTokenEntry(
  entries: readonly AuthTokenEntry[],
  provided: string | undefined
): AuthTokenEntry | undefined {
  if (!provided) {
    return undefined;
  }
  const providedDigest = digest(provided);
  let match: AuthTokenEntry | undefined;
  for (const entry of entries) {
    if (timingSafeEqual(providedDigest, digest(entry.token)) && match === undefined) {
      match = entry;
    }
  }
  return match;
}
