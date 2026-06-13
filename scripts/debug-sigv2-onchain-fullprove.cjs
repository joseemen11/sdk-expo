#!/usr/bin/env node

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const EXPECTED_WCD_SHA256 = "da00a22c09ca91902b1155403c177dca040730ac95142cf65497d6b974baa39a";
const EXPECTED_ZKEY_SHA256 = "e136ef02fd15ccf4c404833da21e6e32485142cb4dd25cd36af4b634c9b8ad4d";
const DEFAULT_ARTIFACT_DIRS = [
  "/mnt/e/CIRCUITOS/privado-id-circuits/credentialAtomicQuerySigV2OnChain",
  "/mnt/e/CIRCUITOS/privado-id-web-sdk/public/circuits/credentialAtomicQuerySigV2OnChain",
  "E:\\CIRCUITOS\\privado-id-circuits\\credentialAtomicQuerySigV2OnChain",
  "E:\\CIRCUITOS\\privado-id-web-sdk\\public\\circuits\\credentialAtomicQuerySigV2OnChain"
];

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const inputPath = args.inputs;
  if (!inputPath) {
    throw new Error("Usage: node scripts/debug-sigv2-onchain-fullprove.cjs --inputs sigv2-onchain-circuit-inputs-debug.json [--wasm <wasm>] [--zkey <zkey>] [--vkey <verification_key.json>] [--mobile-public public.mobile.json]");
  }
  const artifacts = resolveArtifacts(args);
  const loadedInputs = JSON.parse(fs.readFileSync(normalizePath(inputPath), "utf8"));
  const circuitInputs = loadedInputs.inputs && typeof loadedInputs.inputs === "object" ? loadedInputs.inputs : loadedInputs;
  const outputDir = normalizePath(args.out ?? fs.mkdtempSync(path.join(os.tmpdir(), "sigv2-onchain-fullprove-")));
  fs.mkdirSync(outputDir, { recursive: true });

  const snarkjsInputsPath = path.join(outputDir, "sigv2-onchain-circuit-inputs.snarkjs.json");
  const proofDesktopPath = path.join(outputDir, "proof.desktop.json");
  const publicDesktopPath = path.join(outputDir, "public.desktop.json");
  fs.writeFileSync(snarkjsInputsPath, JSON.stringify(circuitInputs));

  const fullprove = runSnarkjs([
    "--yes",
    "snarkjs@0.7.6",
    "groth16",
    "fullprove",
    snarkjsInputsPath,
    artifacts.wasm,
    artifacts.zkey,
    proofDesktopPath,
    publicDesktopPath
  ]);
  const verifyDesktop = fullprove.ok
    ? runSnarkjs(["--yes", "snarkjs@0.7.6", "groth16", "verify", artifacts.vkey, publicDesktopPath, proofDesktopPath])
    : { ok: false, status: "not-run" };
  const publicCompare = comparePublicSignals(args["mobile-public"], publicDesktopPath);

  console.log(JSON.stringify({
    inputs: normalizePath(inputPath),
    snarkjsInputs: snarkjsInputsPath,
    wasm: artifacts.wasm,
    zkey: artifacts.zkey,
    vkey: artifacts.vkey,
    outputDir,
    wcdSha256: artifactHash(args.wcd, EXPECTED_WCD_SHA256),
    zkeySha256: artifactHash(artifacts.zkey, EXPECTED_ZKEY_SHA256),
    fullprove: summarizeCommand(fullprove),
    verifyDesktop: summarizeCommand(verifyDesktop),
    samePublicSignals: publicCompare.samePublicSignals,
    firstDifferentIndex: publicCompare.firstDifferentIndex,
    mobileValue: publicCompare.mobileValue,
    desktopValue: publicCompare.desktopValue,
    conclusion: conclusion(fullprove, verifyDesktop, publicCompare)
  }, null, 2));
}

function resolveArtifacts(args) {
  const wasm = args.wasm ?? findArtifact(["credentialAtomicQuerySigV2OnChain.wasm", "credentialAtomicQuerySigV2OnChain_js/credentialAtomicQuerySigV2OnChain.wasm"]);
  const zkey = args.zkey ?? findArtifact(["credentialAtomicQuerySigV2OnChain.zkey"]);
  const vkey = args.vkey ?? args["verification-key"] ?? findArtifact(["verification_key.json", "credentialAtomicQuerySigV2OnChain.verification_key.json"]);
  if (!wasm) {
    throw new Error("credentialAtomicQuerySigV2OnChain.wasm was not found. Pass --wasm.");
  }
  if (!zkey) {
    throw new Error("credentialAtomicQuerySigV2OnChain.zkey was not found. Pass --zkey.");
  }
  if (!vkey) {
    throw new Error("verification_key.json was not found. Pass --vkey.");
  }
  return {
    wasm: normalizePath(wasm),
    zkey: normalizePath(zkey),
    vkey: normalizePath(vkey)
  };
}

function findArtifact(candidates) {
  for (const dir of DEFAULT_ARTIFACT_DIRS.map(normalizePath)) {
    for (const candidate of candidates) {
      const full = path.join(dir, candidate);
      if (fs.existsSync(full)) {
        return full;
      }
    }
  }
  return undefined;
}

function runSnarkjs(args) {
  const result = spawnSync(npxBin(), args, {
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 16
  });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    command: `npx ${args.join(" ")}`
  };
}

function npxBin() {
  return process.platform === "win32" ? "npx.cmd" : "npx";
}

function summarizeCommand(result) {
  return {
    ok: result.ok,
    status: result.status,
    command: result.command,
    output: truncate(`${result.stdout || ""}${result.stderr ? `\n${result.stderr}` : ""}`)
  };
}

function comparePublicSignals(mobilePublicPath, desktopPublicPath) {
  if (!mobilePublicPath || !fs.existsSync(normalizePath(mobilePublicPath)) || !fs.existsSync(desktopPublicPath)) {
    return {
      samePublicSignals: undefined,
      firstDifferentIndex: undefined,
      mobileValue: undefined,
      desktopValue: undefined
    };
  }
  const mobile = JSON.parse(fs.readFileSync(normalizePath(mobilePublicPath), "utf8")).map(String);
  const desktop = JSON.parse(fs.readFileSync(desktopPublicPath, "utf8")).map(String);
  const max = Math.max(mobile.length, desktop.length);
  for (let index = 0; index < max; index += 1) {
    if (mobile[index] !== desktop[index]) {
      return {
        samePublicSignals: false,
        firstDifferentIndex: index,
        mobileValue: mobile[index],
        desktopValue: desktop[index]
      };
    }
  }
  return {
    samePublicSignals: true,
    firstDifferentIndex: undefined,
    mobileValue: undefined,
    desktopValue: undefined
  };
}

function conclusion(fullprove, verifyDesktop, publicCompare) {
  if (!fullprove.ok) {
    return "input-builder";
  }
  if (!verifyDesktop.ok) {
    return "wasm-zkey-or-desktop-witness";
  }
  if (publicCompare.samePublicSignals === false) {
    return "native-witness-prover-pipeline";
  }
  return "inputs-valid-check-mobile-native-pipeline";
}

function artifactHash(filePath, expectedSha256) {
  if (!filePath) {
    return undefined;
  }
  const normalized = normalizePath(filePath);
  if (!fs.existsSync(normalized)) {
    return { path: normalized, exists: false };
  }
  const sha256 = crypto.createHash("sha256").update(fs.readFileSync(normalized)).digest("hex");
  return {
    path: normalized,
    exists: true,
    sha256,
    matchesExpected: expectedSha256 ? sha256 === expectedSha256 : undefined
  };
}

function normalizePath(value) {
  if (!value) {
    return value;
  }
  return value
    .replace(/^file:\/\//, "")
    .replace(/^E:\\/i, "/mnt/e/")
    .replace(/\\/g, "/");
}

function truncate(value) {
  return value.length > 1000 ? `${value.slice(0, 1000)}...` : value;
}

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    out[item.slice(2)] = argv[index + 1];
    index += 1;
  }
  return out;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
