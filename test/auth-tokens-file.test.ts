import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AuthTokensFileError,
  bearerToken,
  findAuthTokenEntry,
  loadAuthTokensFile,
  parseAuthTokensFile,
} from "../auth-tokens-file.js";

const FILE = "/run/secrets/tokens.json";
const ALICE = {
  name: "alice",
  token: "mcp-client-alice-0123456789",
  gitlabToken: "glpat-alice-0123456789abcd",
};
const BOB = {
  name: "bob",
  token: "mcp-client-bob-0123456789ab",
  gitlabToken: "glpat-bob-0123456789abcdef",
};

function parseError(content: unknown): AuthTokensFileError {
  try {
    parseAuthTokensFile(FILE, typeof content === "string" ? content : JSON.stringify(content));
  } catch (error) {
    if (error instanceof AuthTokensFileError) {
      return error;
    }
    throw error;
  }
  throw new Error("expected AuthTokensFileError");
}

describe("parseAuthTokensFile", () => {
  it("returns the entries, trimmed", () => {
    const entries = parseAuthTokensFile(FILE, JSON.stringify([{ ...ALICE, name: " alice " }, BOB]));
    assert.deepEqual(entries, [ALICE, BOB]);
  });

  it("rejects malformed files", () => {
    assert.match(parseError("{not json").message, /not valid JSON/);
    assert.match(parseError({ alice: ALICE }).message, /non-empty JSON array/);
    assert.match(parseError([]).message, /non-empty JSON array/);
    assert.match(parseError(["alice"]).message, /entry 0: expected an object/);
    assert.match(parseError([{ ...ALICE, gitlabToken: "" }]).message, /entry 0: "gitlabToken"/);
    assert.match(parseError([{ name: "alice", token: ALICE.token }]).message, /"gitlabToken"/);
  });

  it("rejects tokens that remote authorization would not accept", () => {
    assert.match(parseError([{ ...ALICE, token: "short" }]).message, /entry 0: "token" must be/);
    assert.match(
      parseError([{ ...ALICE, gitlabToken: "glpat with spaces 0123456789" }]).message,
      /entry 0: "gitlabToken" must be/
    );
  });

  it("rejects duplicate names and client tokens", () => {
    assert.match(
      parseError([ALICE, { ...BOB, name: "alice" }]).message,
      /entry 1: duplicate "name"/
    );
    assert.match(
      parseError([ALICE, { ...BOB, token: ALICE.token }]).message,
      /entry 1: duplicate "token"/
    );
  });

  it("rejects a client token that is also a GitLab token", () => {
    assert.match(
      parseError([ALICE, { ...BOB, token: ALICE.gitlabToken }]).message,
      /entry 1: "token" equals a "gitlabToken"/
    );
  });

  it("never puts token values into error messages", () => {
    const message = parseError([ALICE, { ...BOB, token: ALICE.token }]).message;
    for (const value of [ALICE.token, ALICE.gitlabToken, BOB.gitlabToken]) {
      assert.ok(!message.includes(value));
    }
  });
});

describe("loadAuthTokensFile", () => {
  it("returns undefined without a path", () => {
    assert.equal(loadAuthTokensFile(undefined), undefined);
    assert.equal(loadAuthTokensFile("  "), undefined);
  });

  it("reads the trimmed path", () => {
    let readPath = "";
    const entries = loadAuthTokensFile(` ${FILE} `, path => {
      readPath = path;
      return JSON.stringify([ALICE]);
    });
    assert.equal(readPath, FILE);
    assert.deepEqual(entries, [ALICE]);
  });

  it("reports read errors by errno code", () => {
    assert.throws(
      () =>
        loadAuthTokensFile(FILE, () => {
          throw Object.assign(new Error("missing"), { code: "ENOENT" });
        }),
      (error: unknown) =>
        error instanceof AuthTokensFileError && error.message.includes(`${FILE} (ENOENT)`)
    );
  });
});

describe("findAuthTokenEntry", () => {
  const entries = [ALICE, BOB];

  it("finds the entry of a client token", () => {
    assert.equal(findAuthTokenEntry(entries, ALICE.token), ALICE);
    assert.equal(findAuthTokenEntry(entries, BOB.token), BOB);
  });

  it("does not match unknown tokens, prefixes or GitLab tokens", () => {
    assert.equal(findAuthTokenEntry(entries, undefined), undefined);
    assert.equal(findAuthTokenEntry(entries, ""), undefined);
    assert.equal(findAuthTokenEntry(entries, ALICE.token.slice(0, -1)), undefined);
    assert.equal(findAuthTokenEntry(entries, `${ALICE.token}x`), undefined);
    assert.equal(findAuthTokenEntry(entries, ALICE.gitlabToken), undefined);
  });
});

describe("bearerToken", () => {
  it("returns the token of a Bearer header", () => {
    assert.equal(bearerToken(`Bearer ${ALICE.token}`), ALICE.token);
    assert.equal(bearerToken(`bearer ${ALICE.token}`), ALICE.token);
  });

  it("returns undefined for anything else", () => {
    assert.equal(bearerToken(undefined), undefined);
    assert.equal(bearerToken(""), undefined);
    assert.equal(bearerToken(ALICE.token), undefined);
    assert.equal(bearerToken(`Basic ${ALICE.token}`), undefined);
    assert.equal(bearerToken(`Bearer ${ALICE.token} extra`), undefined);
  });
});
