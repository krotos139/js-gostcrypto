import { readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";

async function collectTests(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await collectTests(entryPath)));
    else if (entry.isFile() && entry.name.endsWith(".test.mjs"))
      files.push(entryPath);
  }
  return files;
}

const packageEntries = await readdir("packages", { withFileTypes: true });
const tests = [];
for (const entry of packageEntries) {
  if (!entry.isDirectory()) continue;
  const testDirectory = path.join("packages", entry.name, "test");
  try {
    tests.push(...(await collectTests(testDirectory)));
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

tests.sort();
if (tests.length === 0) throw new Error("no test files found");

const child = spawn(process.execPath, ["--test", ...tests], {
  stdio: "inherit",
});
child.once("error", (error) => {
  throw error;
});
child.once("exit", (code, signal) => {
  if (signal !== null) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});
