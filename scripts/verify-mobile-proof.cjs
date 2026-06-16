#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    const key = item.slice(2);
    const next = argv[index + 1];
    if (next && !next.startsWith("--")) {
      args[key] = next;
      index += 1;
    } else {
      args[key] = "true";
    }
  }
  return args;
}

function requireFile(filePath, label) {
  if (!filePath) {
    throw new Error(`${label} path is required.`);
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`${label} file does not exist: ${filePath}`);
  }
  return filePath;
}

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    shell: process.platform === "win32"
  });
  return {
    status: result.status,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim()
  };
}

function snarkjsArgs(args) {
  return ["--yes", "snarkjs@0.7.6", ...args];
}

function main() {
  const args = parseArgs(process.argv);
  const proofPath = requireFile(args.proof ?? "mobile-proof-snarkjs.json", "proof");
  const publicPath = requireFile(args.public ?? "mobile-public-signals.json", "public signals");
  const zkeyPath = args.zkey;
  const vkeyPath =
    args.vkey ??
    (zkeyPath
      ? path.join(
          path.dirname(path.resolve(zkeyPath)),
          "android-credentialAtomicQuerySigV2OnChain-verification_key.json"
        )
      : undefined);

  if (!vkeyPath && !zkeyPath) {
    throw new Error("Either --vkey or --zkey is required.");
  }

  if (zkeyPath && (!vkeyPath || !fs.existsSync(vkeyPath) || args.forceExport === "true")) {
    requireFile(zkeyPath, "zkey");
    const exportResult = run("npx", snarkjsArgs(["zkey", "export", "verificationkey", zkeyPath, vkeyPath]));
    if (exportResult.status !== 0) {
      throw new Error(`snarkjs verification key export failed: ${exportResult.stderr || exportResult.stdout}`);
    }
  }

  requireFile(vkeyPath, "verification key");
  const verifyResult = run("npx", snarkjsArgs(["groth16", "verify", vkeyPath, publicPath, proofPath]));
  const output = {
    ok: verifyResult.status === 0 && /OK!?/i.test(`${verifyResult.stdout}\n${verifyResult.stderr}`),
    status: verifyResult.status,
    verificationKey: vkeyPath,
    proof: proofPath,
    publicSignals: publicPath,
    stdout: verifyResult.stdout,
    stderr: verifyResult.stderr
  };
  console.log(JSON.stringify(output, null, 2));
  if (!output.ok) {
    process.exit(1);
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
