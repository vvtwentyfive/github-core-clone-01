// Lifecycle entrypoint: spawn the vendored Go forge binary, register its port
// with the env, poll until the suite is done, then shut the binary down.
//
// The repository is mounted read-only at /bot in a trial, so the binary is
// copied to a fresh directory under /tmp and executed from there. The binary
// prints "PORT=<n>" as its first stdout line; this launcher reads that line,
// registers the port, and waits. No dependencies: Node built-ins only.

import { spawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const BINARY_NAME = "forge-bin";
const REQUEST_TIMEOUT_MS = 30_000;
const STARTUP_TIMEOUT_MS = 15_000;
const REGISTER_DEADLINE_MS = 60_000;
const SHUTDOWN_GRACE_MS = 5_000;

type SignalName = "SIGTERM" | "SIGINT";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoff(attempt: number): number {
  return Math.min(250 * 2 ** attempt, 2000);
}

// Read the "PORT=<n>" startup line from the child's stdout, with a timeout.
// Once the port is known, the rest of stdout is drained and discarded so the
// child can never block on a full pipe.
async function readPort(child: ChildProcess): Promise<number> {
  const stdout = child.stdout;
  if (!stdout) throw new Error("forge binary has no stdout pipe");
  return new Promise<number>((resolve, reject) => {
    let buffer = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("timed out waiting for the PORT= startup line"));
    }, STARTUP_TIMEOUT_MS);
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    };
    child.once("error", fail);
    child.once("exit", (code) => {
      fail(new Error(`forge binary exited early with code ${code}`));
    });
    stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      buffer += chunk.toString("utf8");
      const nl = buffer.indexOf("\n");
      if (nl === -1) return;
      const line = buffer.slice(0, nl).trim();
      clearTimeout(timer);
      settled = true;
      stdout.removeAllListeners("data");
      stdout.on("data", () => {
        // Drain: never let stdout backpressure stall the server.
      });
      const m = /^PORT=(\d+)$/.exec(line);
      if (!m) {
        reject(
          new Error(`unexpected first stdout line from forge binary: ${JSON.stringify(line)}`),
        );
        return;
      }
      resolve(Number(m[1]));
    });
  });
}

// POST /register until accepted. 409 means another registration won: stop
// registering and go on waiting for done. 400/405 are contract errors and
// abort at once; anything else is retried with backoff until the deadline.
async function register(envUrl: string, port: number): Promise<void> {
  const deadline = Date.now() + REGISTER_DEADLINE_MS;
  let attempt = 0;
  for (;;) {
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.ok) return;
      if (res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register rejected with HTTP ${res.status}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("register rejected")) throw err;
      // Transient failure: back off and retry.
    }
    if (Date.now() >= deadline) throw new Error("register deadline exceeded");
    await sleep(backoff(attempt++));
  }
}

// Poll GET /done until {"done": true}. Each poll is a short request that is
// answered at once; never hold a request open, never exit early. If the
// child dies while waiting, there is no server left to grade, so abort.
async function waitDone(envUrl: string, child: ChildProcess): Promise<void> {
  let attempt = 0;
  for (;;) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error("forge binary exited while waiting for done");
    }
    try {
      const res = await fetch(`${envUrl}/done`, {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // Transient failure: back off and retry.
    }
    await sleep(backoff(attempt++));
  }
}

// Ask the child to stop, then force it if it does not exit in time.
async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, SHUTDOWN_GRACE_MS);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

async function main(): Promise<number> {
  const rawEnvUrl = process.env.MAKEFUN_ENV_URL;
  if (!rawEnvUrl) {
    console.error("MAKEFUN_ENV_URL is not set; nothing to register with");
    return 1;
  }
  const envUrl = rawEnvUrl.replace(/\/+$/, "");

  const here = path.dirname(fileURLToPath(import.meta.url));
  const source = path.join(here, BINARY_NAME);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "forge-"));
  const binPath = path.join(dir, BINARY_NAME);
  fs.copyFileSync(source, binPath);
  fs.chmodSync(binPath, 0o755);

  const child = spawn(binPath, [], {
    env: process.env,
    stdio: ["ignore", "pipe", "inherit"],
  });
  const forward = (signal: SignalName): void => {
    try {
      child.kill(signal);
    } catch {
      // Already gone.
    }
  };
  process.on("SIGTERM", () => forward("SIGTERM"));
  process.on("SIGINT", () => forward("SIGINT"));

  try {
    const port = await readPort(child);
    await register(envUrl, port);
    await waitDone(envUrl, child);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    await stopChild(child);
    return 1;
  }
  await stopChild(child);
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
