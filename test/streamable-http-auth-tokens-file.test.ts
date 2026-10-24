/**
 * STREAMABLE_HTTP_AUTH_TOKENS_FILE: each client authenticates with its own bearer
 * token and the server calls GitLab with the GitLab token mapped to it. Clients
 * never send, and cannot substitute, a GitLab token.
 */

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  cleanupServers,
  findAvailablePort,
  HOST,
  launchServer,
  ServerInstance,
  TransportMode,
} from "./utils/server-launcher.js";
import { findMockServerPort, MockGitLabServer } from "./utils/mock-gitlab-server.js";

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
// A GitLab token the mock accepts but that no entry maps to.
const OUTSIDE_PAT = "glpat-outside-0123456789ab";
// The mock's /user answers with "user_" + the first 8 characters of the token.
const usernameOf = (gitlabToken: string) => `user_${gitlabToken.substring(0, 8)}`;

const SERVER_PATH = path.resolve(process.cwd(), "build/index.js");

interface PostResult {
  status: number;
  sid: string | null;
  text: string;
}

async function post(
  url: string,
  body: Record<string, unknown>,
  headers: Record<string, string>
): Promise<PostResult> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: "2.0", ...body }),
  });
  return { status: res.status, sid: res.headers.get("mcp-session-id"), text: await res.text() };
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

function initialize(url: string, headers: Record<string, string>): Promise<PostResult> {
  return post(
    url,
    {
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "auth-tokens-file-test", version: "1.0.0" },
      },
    },
    headers
  );
}

async function initSession(url: string, headers: Record<string, string>): Promise<string> {
  const res = await initialize(url, headers);
  assert.equal(res.status, 200, res.text);
  assert.ok(res.sid, "initialize must return an Mcp-Session-Id");
  const initialized = await post(
    url,
    { method: "notifications/initialized" },
    { ...headers, "mcp-session-id": res.sid }
  );
  assert.equal(initialized.status, 202, initialized.text);
  return res.sid;
}

function whoami(url: string, headers: Record<string, string>): Promise<PostResult> {
  return post(
    url,
    { id: 2, method: "tools/call", params: { name: "whoami", arguments: {} } },
    headers
  );
}

function writeTokensFile(dir: string, entries: unknown): string {
  const file = path.join(dir, "tokens.json");
  fs.writeFileSync(file, JSON.stringify(entries), { mode: 0o600 });
  return file;
}

/** Starts the server with a configuration it must refuse; returns exit code and stderr. */
async function runRejected(
  env: Record<string, string>
): Promise<{ code: number | null; stderr: string }> {
  const port = await findAvailablePort(3960);
  const child = spawn("node", [SERVER_PATH], {
    env: {
      ...process.env,
      GITLAB_API_URL: "https://gitlab.example.com/api/v4",
      HOST,
      PORT: String(port),
      STREAMABLE_HTTP: "true",
      REMOTE_AUTHORIZATION: "true",
      GITLAB_MCP_OAUTH: "false",
      GITLAB_PERSONAL_ACCESS_TOKEN: "",
      STREAMABLE_HTTP_AUTH_TOKEN: "",
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stdout?.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
  child.stderr?.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
  const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
  const [code] = await once(child, "exit");
  clearTimeout(timer);
  return { code: code as number | null, stderr };
}

describe("Streamable HTTP with STREAMABLE_HTTP_AUTH_TOKENS_FILE", () => {
  let mockGitLab: MockGitLabServer;
  const servers: ServerInstance[] = [];
  let tmpDir = "";
  let tokensFile = "";
  let baseUrl = "";
  let mcpUrl = "";
  let output = "";

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitlab-mcp-auth-tokens-"));
    tokensFile = writeTokensFile(tmpDir, [ALICE, BOB]);

    mockGitLab = new MockGitLabServer({
      port: await findMockServerPort(),
      validTokens: [ALICE.gitlabToken, BOB.gitlabToken, OUTSIDE_PAT],
    });
    await mockGitLab.start();
    // Full user object, as whoami validates it; the username identifies the token.
    mockGitLab.addMockHandler("get", "/user", (req, res) => {
      const token = (req as { gitlabToken?: string }).gitlabToken ?? "";
      res.json({
        id: 1,
        username: usernameOf(token),
        name: "Test User",
        state: "active",
        avatar_url: null,
        web_url: "https://gitlab.mock/user",
        created_at: "2024-01-01T00:00:00Z",
        bio: null,
        location: null,
        public_email: null,
        website_url: null,
        organization: null,
        job_title: null,
        email: null,
        last_sign_in_at: null,
        confirmed_at: null,
        last_activity_on: null,
      });
    });

    const port = await findAvailablePort(3940);
    baseUrl = `http://${HOST}:${port}`;
    const server = await launchServer({
      mode: TransportMode.STREAMABLE_HTTP,
      port,
      timeout: 10_000,
      env: {
        STREAMABLE_HTTP: "true",
        REMOTE_AUTHORIZATION: "true",
        STREAMABLE_HTTP_AUTH_TOKENS_FILE: tokensFile,
        GITLAB_API_URL: `${mockGitLab.getUrl()}/api/v4`,
        LOG_LEVEL: "debug",
      },
    });
    servers.push(server);
    server.process.stdout?.on("data", (chunk: Buffer) => (output += chunk.toString()));
    server.process.stderr?.on("data", (chunk: Buffer) => (output += chunk.toString()));
    mcpUrl = `${baseUrl}/mcp`;
  });

  after(async () => {
    cleanupServers(servers);
    await mockGitLab?.stop();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("each client acts with its own mapped GitLab token", async () => {
    for (const client of [ALICE, BOB]) {
      const sid = await initSession(mcpUrl, bearer(client.token));
      const res = await whoami(mcpUrl, { ...bearer(client.token), "mcp-session-id": sid });
      assert.equal(res.status, 200, res.text);
      assert.ok(res.text.includes(usernameOf(client.gitlabToken)), res.text);
    }
  });

  test("requests without a known client token are rejected", async () => {
    assert.equal((await initialize(mcpUrl, {})).status, 401);
    assert.equal((await initialize(mcpUrl, bearer("mcp-client-unknown-0123456789"))).status, 401);
    // A GitLab token is not a client token, whether mapped or not.
    assert.equal((await initialize(mcpUrl, bearer(ALICE.gitlabToken))).status, 401);
    assert.equal((await initialize(mcpUrl, { "Private-Token": OUTSIDE_PAT })).status, 401);
    assert.equal((await initialize(mcpUrl, { "JOB-TOKEN": OUTSIDE_PAT })).status, 401);
  });

  test("a client cannot substitute its own GitLab token", async () => {
    const headers = { ...bearer(ALICE.token), "Private-Token": OUTSIDE_PAT };
    const sid = await initSession(mcpUrl, headers);
    const res = await whoami(mcpUrl, { ...headers, "mcp-session-id": sid });
    assert.equal(res.status, 200, res.text);
    assert.ok(res.text.includes(usernameOf(ALICE.gitlabToken)), res.text);
    assert.ok(!res.text.includes(usernameOf(OUTSIDE_PAT)), res.text);
  });

  test("a session id alone does not authenticate", async () => {
    const sid = await initSession(mcpUrl, bearer(ALICE.token));
    assert.equal((await whoami(mcpUrl, { "mcp-session-id": sid })).status, 401);
    assert.equal(
      (await whoami(mcpUrl, { ...bearer("mcp-client-unknown-0123456789"), "mcp-session-id": sid }))
        .status,
      401
    );
    const stream = await fetch(mcpUrl, {
      method: "GET",
      headers: { Accept: "text/event-stream", "mcp-session-id": sid },
    });
    await stream.body?.cancel();
    assert.equal(stream.status, 401);
    const del = await fetch(mcpUrl, { method: "DELETE", headers: { "mcp-session-id": sid } });
    await del.text();
    assert.equal(del.status, 401);

    const own = await whoami(mcpUrl, { ...bearer(ALICE.token), "mcp-session-id": sid });
    assert.equal(own.status, 200, own.text);
  });

  test("another client's token on a session acts as that client, not as the owner", async () => {
    const sid = await initSession(mcpUrl, bearer(ALICE.token));
    const res = await whoami(mcpUrl, { ...bearer(BOB.token), "mcp-session-id": sid });
    assert.equal(res.status, 200, res.text);
    assert.ok(res.text.includes(usernameOf(BOB.gitlabToken)), res.text);
    assert.ok(!res.text.includes(usernameOf(ALICE.gitlabToken)), res.text);
  });

  test("downloads map the client token too", async () => {
    const unauthenticated = await fetch(
      `${baseUrl}/downloads/job-artifacts?project_id=1&job_id=1`,
      {
        headers: { "Private-Token": OUTSIDE_PAT },
      }
    );
    await unauthenticated.text();
    assert.equal(unauthenticated.status, 401);
  });

  test("tokens never appear in the request logs", async () => {
    // Give the buffered logger a flush interval.
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.ok(output.length > 0, "expected request logs");
    for (const value of [ALICE.token, ALICE.gitlabToken, BOB.token, BOB.gitlabToken]) {
      assert.ok(!output.includes(value), "a token value was logged");
    }
  });
});

describe("STREAMABLE_HTTP_AUTH_TOKENS_FILE startup validation", () => {
  let tmpDir = "";
  let tokensFile = "";

  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitlab-mcp-auth-tokens-"));
    tokensFile = writeTokensFile(tmpDir, [ALICE]);
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const rejected: Array<[string, Record<string, string>, RegExp]> = [
    [
      "without remote authorization",
      {
        REMOTE_AUTHORIZATION: "false",
        GITLAB_PERSONAL_ACCESS_TOKEN: "glpat-server-0123456789abcd",
      },
      /requires STREAMABLE_HTTP=true and REMOTE_AUTHORIZATION=true/,
    ],
    [
      "together with STREAMABLE_HTTP_AUTH_TOKEN",
      { STREAMABLE_HTTP_AUTH_TOKEN: "static-mcp-token-0123456789" },
      /mutually exclusive/,
    ],
    [
      "with a client-chosen API URL",
      { ENABLE_DYNAMIC_API_URL: "true" },
      /not compatible with ENABLE_DYNAMIC_API_URL/,
    ],
  ];

  for (const [label, env, message] of rejected) {
    test(`refuses to start ${label}`, async () => {
      const run = await runRejected({ STREAMABLE_HTTP_AUTH_TOKENS_FILE: tokensFile, ...env });
      assert.notEqual(run.code, 0);
      assert.match(run.stderr, message);
    });
  }

  test("refuses to start with an invalid tokens file", async () => {
    const bad = path.join(tmpDir, "bad.json");
    fs.writeFileSync(bad, JSON.stringify([ALICE, { ...BOB, token: ALICE.token }]));
    const run = await runRejected({ STREAMABLE_HTTP_AUTH_TOKENS_FILE: bad });
    assert.notEqual(run.code, 0);
    assert.match(run.stderr, /duplicate "token"/);
    assert.ok(!run.stderr.includes(ALICE.token));
  });
});
