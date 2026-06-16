#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

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

function loadDemoEnv() {
  const envPath = path.join(__dirname, "..", "example", "demo-expo", ".env");
  if (!fs.existsSync(envPath)) {
    return;
  }
  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) {
      continue;
    }
    const separator = trimmed.indexOf("=");
    const key = trimmed.slice(0, separator);
    const value = trimmed.slice(separator + 1);
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function summarizeProof(proof) {
  return {
    root: proof?.root?.toString?.() ?? String(proof?.root),
    existence: Boolean(proof?.existence),
    siblingsCount: Array.isArray(proof?.siblings) ? proof.siblings.length : undefined,
    index: proof?.index?.toString?.() ?? String(proof?.index),
    value: proof?.value?.toString?.() ?? String(proof?.value),
    auxExistence: Boolean(proof?.auxExistence),
    auxIndex: proof?.auxIndex?.toString?.() ?? String(proof?.auxIndex),
    auxValue: proof?.auxValue?.toString?.() ?? String(proof?.auxValue)
  };
}

function errorSummary(error) {
  return error instanceof Error ? error.message.split(/\r?\n/)[0].slice(0, 220) : String(error).slice(0, 220);
}

async function main() {
  loadDemoEnv();
  const args = parseArgs(process.argv);
  const holderDid = args.holderDid;
  const rpcUrl = args.rpcUrl ?? process.env.EXPO_PUBLIC_RPC_URL;
  const stateContractAddress = args.stateContractAddress ?? process.env.EXPO_PUBLIC_STATE_CONTRACT_ADDRESS;
  const chainId = Number(args.chainId ?? process.env.EXPO_PUBLIC_CHAIN_ID ?? 80002);

  if (!holderDid) {
    throw new Error("Usage: node scripts/debug-gist-state-contract.cjs --holderDid <did>");
  }
  if (!rpcUrl || !stateContractAddress) {
    throw new Error("rpcUrl and stateContractAddress are required.");
  }

  const { DID } = require("@iden3/js-iden3-core");
  const { EthStateStorage } = require("../node_modules/@0xpolygonid/js-sdk/dist/node/cjs/index.cjs");
  const { ReadOnlyMobileGistProofSource } = require("../dist/auth/MobileGistProofSource.js");

  const did = DID.parse(holderDid);
  const id = DID.idFromDID(did).bigInt();
  const ethConfig = {
    url: rpcUrl,
    contractAddress: stateContractAddress,
    chainId,
    defaultGasLimit: 600000,
    confirmationBlockCount: 5,
    confirmationTimeout: 600000,
    receiptTimeout: 600000,
    rpcResponseTimeout: 5000,
    waitReceiptCycleTime: 30000,
    waitBlockCycleTime: 3000
  };

  const output = {
    id: id.toString(),
    rpcUrlHost: new URL(rpcUrl).host,
    stateContractAddress,
    official: undefined,
    mobile: undefined
  };

  try {
    const official = new EthStateStorage(ethConfig, { disableCache: true });
    output.official = {
      ok: true,
      proof: summarizeProof(await official.getGISTProof(id))
    };
  } catch (error) {
    output.official = { ok: false, error: errorSummary(error) };
  }

  try {
    const mobile = new ReadOnlyMobileGistProofSource({
      rpcUrl,
      chainId,
      stateContractAddress,
      preferStateContract: true
    });
    const proof = await mobile.getGISTProof(holderDid, { allowResolverFallback: false });
    output.mobile = {
      ok: true,
      proof: summarizeProof(proof),
      debug: mobile.getLastDebugInfo()
    };
  } catch (error) {
    output.mobile = { ok: false, error: errorSummary(error) };
  }

  console.log(JSON.stringify(output, null, 2));
}

main().catch((error) => {
  console.error(errorSummary(error));
  process.exit(1);
});
