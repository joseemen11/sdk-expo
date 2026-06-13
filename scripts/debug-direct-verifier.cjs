#!/usr/bin/env node

const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { ethers } = require("ethers");

const DEFAULT_RPC_URL = "https://rpc-amoy.polygon.technology";
const DEFAULT_VERIFIER = "0x0ce200c9557BB64ee9E82452646b084e77Aaeb51";
const EXPECTED_WCD_SHA256 = "da00a22c09ca91902b1155403c177dca040730ac95142cf65497d6b974baa39a";
const EXPECTED_ZKEY_SHA256 = "e136ef02fd15ccf4c404833da21e6e32485142cb4dd25cd36af4b634c9b8ad4d";
const SNARK_FIELD = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

const verifierAbi = [
  "function verify(uint256[2] a,uint256[2][2] b,uint256[2] c,uint256[] input) view returns (bool)",
  "function verifyProof(uint256[2] a,uint256[2][2] b,uint256[2] c,uint256[11] pubSignals) view returns (bool)"
];

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const proofPath = args.proof ?? args.input ?? process.env.PROOF_JSON;
  if (!proofPath) {
    throw new Error("Usage: node scripts/debug-direct-verifier.cjs --proof <prepared-proof.json> [--rpc <url>] [--verifier <address>] [--wcd <path>] [--zkey <path>]");
  }

  const loaded = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  const prepared = loaded.preparedProof ?? loaded;
  const calldata = toCalldata(prepared);
  const provider = new ethers.JsonRpcProvider(args.rpc ?? process.env.RPC_URL ?? DEFAULT_RPC_URL);
  const verifier = new ethers.Contract(args.verifier ?? process.env.VERIFIER_ADDRESS ?? DEFAULT_VERIFIER, verifierAbi, provider);

  const variants = {
    current: calldata.b,
    swapInner: swapInner(calldata.b),
    swapRows: swapRows(calldata.b),
    swapRowsInner: swapInner(swapRows(calldata.b))
  };
  const results = {};
  for (const [name, b] of Object.entries(variants)) {
    results[name] = await verifyVariant(verifier, calldata.a, b, calldata.c, calldata.publicSignals);
  }

  const artifactChecks = {
    wcd: args.wcd ? hashFile(args.wcd, EXPECTED_WCD_SHA256) : undefined,
    zkey: args.zkey ? hashFile(args.zkey, EXPECTED_ZKEY_SHA256) : undefined
  };
  const snarkjsVerifyMobileProof = args.vkey
    ? runSnarkjsVerifyMobileProof(args.vkey, prepared, calldata.publicSignals)
    : "not-run";

  console.log(JSON.stringify({
    verifier: args.verifier ?? process.env.VERIFIER_ADDRESS ?? DEFAULT_VERIFIER,
    publicSignalsCount: calldata.publicSignals.length,
    allPublicSignalsBelowField: calldata.publicSignals.every((value) => BigInt(value) < SNARK_FIELD),
    publicSignalsSource: loaded.publicSignalsSource ?? prepared.publicSignalsSource ?? "rapidsnark-or-exported",
    proofSource: loaded.proofSource ?? prepared.proofSource ?? "rapidsnark-or-exported",
    snarkjsVerifyMobileProof,
    piBVariants: {
      directVerifierCurrent: results.current.ok,
      directVerifierSwapInner: results.swapInner.ok,
      directVerifierSwapRows: results.swapRows.ok,
      directVerifierSwapRowsInner: results.swapRowsInner.ok
    },
    errors: compactErrors(results),
    artifactChecks
  }, null, 2));
}

async function verifyVariant(verifier, a, b, c, publicSignals) {
  try {
    const ok = await verifier.verify.staticCall(a, b, c, publicSignals);
    return { ok: Boolean(ok) };
  } catch (error) {
    return { ok: false, error: safeError(error) };
  }
}

function toCalldata(input) {
  const proof = input.proof ?? input;
  const publicSignals = normalizeArray(input.publicSignals ?? input.pub_signals ?? input.inputs, "publicSignals");
  const a = input.a ? tuple2(input.a, "a") : tuple2(normalizeArray(proof.pi_a ?? proof.piA, "proof.pi_a").slice(0, 2), "proof.pi_a");
  const b = input.b ? tuple2x2(input.b, "b") : preparePiB(proof.pi_b ?? proof.piB);
  const c = input.c ? tuple2(input.c, "c") : tuple2(normalizeArray(proof.pi_c ?? proof.piC, "proof.pi_c").slice(0, 2), "proof.pi_c");
  if (publicSignals.length !== 11) {
    throw new Error(`Expected 11 publicSignals for credentialAtomicQuerySigV2OnChain, got ${publicSignals.length}.`);
  }
  return { publicSignals, a, b, c };
}

function preparePiB(value) {
  const b = tuple2x2(value, "proof.pi_b");
  return [
    [b[0][1], b[0][0]],
    [b[1][1], b[1][0]]
  ];
}

function normalizeArray(value, field) {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array.`);
  }
  return value.map((entry, index) => decimalString(entry, `${field}[${index}]`));
}

function tuple2(value, field) {
  const values = normalizeArray(value, field);
  if (values.length < 2) {
    throw new Error(`${field} must contain at least 2 values.`);
  }
  return [values[0], values[1]];
}

function tuple2x2(value, field) {
  if (!Array.isArray(value) || value.length < 2) {
    throw new Error(`${field} must be uint256[2][2].`);
  }
  return [tuple2(value[0], `${field}[0]`), tuple2(value[1], `${field}[1]`)];
}

function swapInner(b) {
  return b.map((row) => [row[1], row[0]]);
}

function swapRows(b) {
  return [b[1], b[0]];
}

function decimalString(value, field) {
  if (typeof value === "bigint" && value >= 0n) {
    return value.toString();
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return value;
  }
  throw new Error(`${field} must be a decimal uint256 string.`);
}

function hashFile(path, expectedSha256) {
  const normalizedPath = path.replace(/^file:\/\//, "");
  const hash = crypto.createHash("sha256").update(fs.readFileSync(normalizedPath)).digest("hex");
  return {
    path: normalizedPath,
    sha256: hash,
    matchesExpected: hash === expectedSha256
  };
}

function runSnarkjsVerifyMobileProof(vkeyPath, prepared, publicSignals) {
  const proof = prepared.proof ?? prepared;
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "sigv2-mobile-verify-"));
  const proofPath = path.join(outputDir, "proof.mobile.json");
  const publicPath = path.join(outputDir, "public.mobile.json");
  fs.writeFileSync(proofPath, JSON.stringify(proof));
  fs.writeFileSync(publicPath, JSON.stringify(publicSignals));
  const result = spawnSync(npxBin(), ["--yes", "snarkjs@0.7.6", "groth16", "verify", vkeyPath, publicPath, proofPath], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 8
  });
  if (result.status === 0) {
    return "valid";
  }
  return `invalid: ${safeError(`${result.stdout ?? ""}${result.stderr ?? ""}`)}`;
}

function npxBin() {
  return process.platform === "win32" ? "npx.cmd" : "npx";
}

function compactErrors(results) {
  return Object.fromEntries(
    Object.entries(results)
      .filter(([, result]) => result.error)
      .map(([name, result]) => [name, result.error])
  );
}

function safeError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message.length > 240 ? `${message.slice(0, 240)}...` : message;
}

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    const key = item.slice(2);
    out[key] = argv[index + 1];
    index += 1;
  }
  return out;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
