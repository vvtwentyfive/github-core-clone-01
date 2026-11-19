// Trial launcher for the github-core-clone-01 forge.
//
// This file serves nothing on its own. It supervises the forge
// binary that sits beside it:
//
//   1. start ./forge-bin and watch its stdout for a PORT=<n> line;
//   2. report that port to the trial environment (POST /register);
//   3. poll GET /done until the suite says the trial is finished;
//   4. stop the forge and leave with exit code 0.
//
// The forge binds an ephemeral port of its own choosing, so this
// launcher never binds anything itself -- in particular never
// port 8080, where the suite listens.
//
// The file uses only dynamic imports, plain functions and the
// Node standard library, with no top-level await, so it loads the
// same way whether the surrounding package treats .ts files as
// CommonJS or as ESM.

const ENV_URL_NAME = "MAKEFUN_ENV_URL";
const FORGE_FILE = "forge-bin";
const PORT_LINE = /^PORT=(\d+)$/;

// One HTTP attempt may take at most this long before it counts as failed.
const ATTEMPT_TIMEOUT_MS = 30_000;
// The pause between attempts starts here, doubles after each failure,
// and never grows past LONGEST_PAUSE_MS.
const FIRST_PAUSE_MS = 250;
const LONGEST_PAUSE_MS = 2000;
// How long to wait for the forge to exit after SIGTERM before SIGKILL.
const STOP_GRACE_MS = 5000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function growPause(currentMs) {
  return Math.min(currentMs * 2, LONGEST_PAUSE_MS);
}

function shortError(err) {
  return err instanceof Error ? err.message : String(err);
}

function stripTrailingSlashes(raw) {
  return raw.replace(/\/+$/, "");
}

// Read and drop a response body so its connection can be reused.
async function drain(response) {
  try {
    await response.arrayBuffer();
  } catch {
    // An unreadable body changes nothing about what we do next.
  }
}

// Start the forge binary, keeping its stderr on ours and piping
// its stdout so we can watch for the PORT= line.
function startForge(spawn, binaryPath) {
  return spawn(binaryPath, [], { stdio: ["ignore", "pipe", "inherit"] });
}

// Resolve with the port number from the first PORT=<n> stdout line.
// Reject if the forge dies or cannot start before printing one.
function waitForPort(child) {
  return new Promise((resolve, reject) => {
    const out = child.stdout;
    if (!out) {
      reject(new Error("could not read the forge's stdout"));
      return;
    }
    let buffer = "";
    let settled = false;
    const fail = (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };
    child.on("error", (err) => fail(new Error(`could not start ${FORGE_FILE}: ${shortError(err)}`)));
    child.on("exit", (code, signal) =>
      fail(new Error(`${FORGE_FILE} left before printing its port (code ${code}, signal ${signal})`)),
    );
    out.on("data", (chunk) => {
      if (settled) return;
      buffer += chunk.toString("utf8");
      let newline = buffer.indexOf("\n");
      while (newline !== -1) {
        const line = buffer.slice(0, newline).replace(/\r$/, "").trim();
        buffer = buffer.slice(newline + 1);
        const match = PORT_LINE.exec(line);
        if (match) {
          settled = true;
          resolve(Number(match[1]));
          return;
        }
        newline = buffer.indexOf("\n");
      }
    });
  });
}

// Tell the trial environment which port the forge listens on.
// 200 and 409 both mean the registration landed; 400 and 405 mean
// the request itself is wrong, so retrying cannot help and we stop.
// Anything else (another status, a dropped connection, a timeout)
// is retried with the growing pause.
async function registerPort(base, port) {
  const target = `${base}/register`;
  let pauseMs = FIRST_PAUSE_MS;
  for (;;) {
    let response;
    try {
      response = await fetch(target, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(ATTEMPT_TIMEOUT_MS),
      });
    } catch (err) {
      process.stderr.write(`register: ${shortError(err)}; trying again in ${pauseMs} ms\n`);
      await sleep(pauseMs);
      pauseMs = growPause(pauseMs);
      continue;
    }
    if (response.status === 200 || response.status === 409) {
      await drain(response);
      return;
    }
    if (response.status === 400 || response.status === 405) {
      await drain(response);
      throw new Error(`register refused with HTTP ${response.status}; giving up`);
    }
    await drain(response);
    process.stderr.write(`register: HTTP ${response.status}; trying again in ${pauseMs} ms\n`);
    await sleep(pauseMs);
    pauseMs = growPause(pauseMs);
  }
}

// Ask the environment whether the trial is over, until it says so.
// A "not yet" answer, a failed attempt and an unreadable answer all
// lead to the same thing: pause, then ask again. While polling, also
// notice if the forge has died underneath us.
async function waitUntilDone(base, isForgeAlive) {
  const target = `${base}/done`;
  let pauseMs = FIRST_PAUSE_MS;
  for (;;) {
    if (!isForgeAlive()) {
      throw new Error(`${FORGE_FILE} stopped while waiting for the trial to finish`);
    }
    let response;
    try {
      response = await fetch(target, {
        method: "GET",
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(ATTEMPT_TIMEOUT_MS),
      });
    } catch (err) {
      process.stderr.write(`done poll: ${shortError(err)}; trying again in ${pauseMs} ms\n`);
      await sleep(pauseMs);
      pauseMs = growPause(pauseMs);
      continue;
    }
    if (response.ok) {
      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }
      if (payload !== null && payload.done === true) return;
    } else {
      await drain(response);
      process.stderr.write(`done poll: HTTP ${response.status}; trying again in ${pauseMs} ms\n`);
    }
    await sleep(pauseMs);
    pauseMs = growPause(pauseMs);
  }
}

// Ask the forge to stop, then insist if it lingers.
async function stopForge(child, childDone) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const finished = await Promise.race([
    childDone,
    sleep(STOP_GRACE_MS).then(() => null),
  ]);
  if (finished === null) child.kill("SIGKILL");
}

async function main() {
  const childProcess = await import("node:child_process");
  const path = await import("node:path");

  const rawBase = process.env[ENV_URL_NAME];
  if (!rawBase) {
    process.stderr.write(`error: ${ENV_URL_NAME} is not set; the trial environment did not provide it\n`);
    return 1;
  }
  const base = stripTrailingSlashes(rawBase);
  const here = path.dirname(process.argv[1]);
  const child = startForge(childProcess.spawn, path.join(here, FORGE_FILE));

  let childExit = null;
  const childDone = new Promise((resolve) => {
    child.on("exit", (code, signal) => {
      childExit = { code, signal };
      resolve(childExit);
    });
  });

  try {
    const port = await waitForPort(child);
    process.stderr.write(`forge listening on port ${port}\n`);
    await registerPort(base, port);
    process.stderr.write(`registered port ${port} with the trial environment\n`);
    await waitUntilDone(base, () => childExit === null);
    process.stderr.write(`trial done; stopping the forge\n`);
    return 0;
  } finally {
    await stopForge(child, childDone);
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`launcher failed: ${shortError(err)}\n`);
    process.exitCode = 1;
  },
);
