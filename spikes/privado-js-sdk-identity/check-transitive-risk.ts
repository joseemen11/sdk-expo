import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = "node_modules/@0xpolygonid/js-sdk";
const PATTERNS = [
  "BrowserDataSource",
  "LocalStoragePrivateKeyStore",
  "MerkleTreeLocalStorage",
  "localStorage",
  "IndexedDB",
  "snarkjs",
  "ffjavascript",
  "NativeProver"
];

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      return walk(path);
    }
    return /\.(ts|js|d\.ts)$/.test(path) ? [path] : [];
  });
}

if (!existsSync(ROOT)) {
  throw new Error("@0xpolygonid/js-sdk is not installed.");
}

const matches = [];
for (const file of walk(ROOT)) {
  const source = readFileSync(file, "utf8");
  for (const pattern of PATTERNS) {
    if (source.toLowerCase().includes(pattern.toLowerCase())) {
      matches.push({ file, pattern });
    }
  }
}

console.log(JSON.stringify(matches, null, 2));
