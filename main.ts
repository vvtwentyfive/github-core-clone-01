// main.ts — thin launcher for the github-core-clone-01 forge.
//
// The Go forge is vendored beside this file as "forge-bin". The trial mounts
// the repo read-only at /bot, so the launcher copies the binary into a fresh
// directory under the OS temp dir, makes it executable, spawns it, reads the
// PORT=<n> line it prints on stdout, registers that port with the suite env,
// then polls /done until the suite finishes. Node built-ins only.
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const PORT_LINE_TIMEOUT_MS = 15_000;
const REGISTER_DEADLINE_MS = 60_000;
const REQUEST_TIMEOUT_MS = 30_000;
const SHUTDOWN_GRACE_MS = 5_000;
const KILL_WAIT_MS = 2_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fatal(message: string): never {
  console.error(`main.ts: ${message}`);
  process.exit(1);
}

async function main(): Promise<number> {
  const envUrlRaw = process.env.MAKEFUN_ENV_URL;
  if (!envUrlRaw) {
    console.error("main.ts: MAKEFUN_ENV_URL is not set");
    return 1;
  }
  const envUrl = envUrlRaw.replace(/\/+$/, "");

  // Copy the vendored binary to a fresh temp dir (repo is read-only in-trial)
  // and make it executable before running it.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const stagedDir = fs.mkdtempSync(path.join(os.tmpdir(), "forge-"));
  const stagedBin = path.join(stagedDir, "forge-bin");
  fs.copyFileSync(path.join(here, "forge-bin"), stagedBin);
  fs.chmodSync(stagedBin, 0o755);

  const child = spawn(stagedBin, [], {
    stdio: ["ignore", "pipe", "inherit"],
    env: process.env,
  });

  let childExited = false;
  let childCode: number | null = null;
  let spawnError: Error | null = null;
  const childExit = new Promise<void>((resolve) => {
    child.on("exit", (code) => {
      childExited = true;
      childCode = code;
      resolve();
    });
  });
  child.on("error", (err) => {
    // A spawn failure (missing/unrunnable binary) may never produce an
    // "exit" event, so record it for the port-line wait to reject at once.
    spawnError = err;
    console.error(`main.ts: failed to spawn forge binary: ${err.message}`);
  });

  // Forward termination signals to the child.
  const forward = (signal: NodeJS.Signals): void => {
    if (!childExited) child.kill(signal);
  };
  process.on("SIGTERM", () => forward("SIGTERM"));
  process.on("SIGINT", () => forward("SIGINT"));

  const stopChild = async (): Promise<void> => {
    if (childExited) return;
    child.kill("SIGTERM");
    const exited = await Promise.race([
      childExit.then(() => true),
      sleep(SHUTDOWN_GRACE_MS).then(() => false),
    ]);
    if (!exited && !childExited) {
      child.kill("SIGKILL");
      // Never hang shutdown forever if the kill itself somehow fails.
      await Promise.race([childExit, sleep(KILL_WAIT_MS)]);
    }
  };

  try {
    // Read the first stdout line: it must be PORT=<number>.
    const port = await new Promise<number>((resolve, reject) => {
      if (!child.stdout) {
        reject(new Error("forge stdout is not piped"));
        return;
      }
      if (spawnError) {
        reject(new Error(`forge failed to spawn: ${spawnError.message}`));
        return;
      }
      let buf = "";
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error("timed out waiting for PORT=<n> line from forge"));
        }
      }, PORT_LINE_TIMEOUT_MS);
      const fail = (err: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      };
      child.on("exit", () => {
        if (!settled) {
          fail(new Error("forge exited before printing PORT=<n>"));
        }
      });
      child.on("error", (err) => {
        if (!settled) fail(new Error(`forge failed to spawn: ${err.message}`));
      });
      // One listener for the whole run: before the port line it buffers until
      // the newline; afterwards it keeps draining stdout and discarding it so
      // the child can never block on a full pipe.
      child.stdout.on("data", (chunk: Buffer) => {
        if (settled) return;
        buf += chunk.toString("utf8");
        const nl = buf.indexOf("\n");
        if (nl === -1) return;
        const line = buf.slice(0, nl).trim();
        const m = /^PORT=([0-9]+)$/.exec(line);
        if (!m) {
          fail(new Error(`malformed first stdout line from forge: ${JSON.stringify(line)}`));
          return;
        }
        const parsed = Number(m[1]);
        if (parsed < 1 || parsed > 65535) {
          fail(new Error(`port out of range in first stdout line: ${JSON.stringify(line)}`));
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve(parsed);
      });
    });
    console.error(`main.ts: forge listening on port ${port}`);

    // Register the port with the suite env, retrying with exponential
    // backoff until the 60s deadline. 409 means another registration won:
    // stop retrying and proceed. 400/405 is a contract error: abort at once.
    const registerUrl = `${envUrl}/register`;
    const deadline = Date.now() + REGISTER_DEADLINE_MS;
    let delay = 250;
    for (;;) {
      if (Date.now() >= deadline) {
        console.error("main.ts: register deadline (60s) exceeded");
        return 1;
      }
      try {
        const res = await fetch(registerUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ port }),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        if (res.status === 409) break;
        if (res.status === 400 || res.status === 405) {
          await res.text().catch(() => undefined);
          console.error(`main.ts: register rejected with HTTP ${res.status}`);
          return 1;
        }
        if (res.ok) break;
        await res.text().catch(() => undefined);
        console.error(`main.ts: register HTTP ${res.status}, retrying`);
      } catch (err) {
        console.error(`main.ts: register failed: ${(err as Error).message}, retrying`);
      }
      if (Date.now() >= deadline) {
        console.error("main.ts: register deadline (60s) exceeded");
        return 1;
      }
      await sleep(Math.min(delay, Math.max(0, deadline - Date.now())));
      delay = Math.min(delay * 2, 2000);
    }
    console.error("main.ts: registered with env");

    // Poll /done with backoff until the suite reports done. Never hold a
    // request open: each poll is a single short request. If the child exits
    // while waiting, abort with an error.
    const doneUrl = `${envUrl}/done`;
    let pollDelay = 500;
    for (;;) {
      if (childExited) {
        console.error(`main.ts: forge exited (code ${childCode}) while waiting for done`);
        return 1;
      }
      try {
        const res = await fetch(doneUrl, {
          method: "GET",
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        if (res.ok) {
          const body = (await res.json()) as { done?: unknown };
          if (body.done === true) {
            console.error("main.ts: suite done");
            return 0;
          }
        } else {
          await res.text().catch(() => undefined);
          console.error(`main.ts: /done HTTP ${res.status}, retrying`);
        }
      } catch (err) {
        console.error(`main.ts: /done poll failed: ${(err as Error).message}, retrying`);
      }
      await Promise.race([sleep(pollDelay), childExit]);
      pollDelay = Math.min(pollDelay * 2, 2000);
    }
  } catch (err) {
    console.error(`main.ts: ${(err as Error).message}`);
    return 1;
  } finally {
    await stopChild();
  }
}

main().then(
  (code) => process.exit(code),
  (err) => fatal(String((err as Error)?.message ?? err)),
);
