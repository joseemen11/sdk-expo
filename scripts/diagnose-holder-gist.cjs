const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

function readEnv(filePath) {
  const result = {};
  const text = fs.readFileSync(filePath, "utf8");
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    result[key] = value;
  }
  return result;
}

function toHex32(value) {
  const hex = BigInt(value).toString(16).padStart(64, "0");
  return "0x" + hex;
}

function nonZeroCount(values) {
  return values.filter((v) => BigInt(v.toString()) !== 0n).length;
}

async function main() {
  const envPath = path.join("example", "demo-expo", ".env");
  const env = readEnv(envPath);

  const rpcUrl = env.EXPO_PUBLIC_RPC_URL;
  const stateContractAddress = env.EXPO_PUBLIC_STATE_CONTRACT_ADDRESS;

  if (!rpcUrl) throw new Error("EXPO_PUBLIC_RPC_URL not found in example/demo-expo/.env");
  if (!stateContractAddress) throw new Error("EXPO_PUBLIC_STATE_CONTRACT_ADDRESS not found in example/demo-expo/.env");

  const debug = JSON.parse(
    fs.readFileSync("debug/latest/sigv2-onchain-circuit-inputs-debug.json", "utf8")
  );

  const inputs = debug.inputs ?? debug;

  const userGenesisID = BigInt(inputs.userGenesisID);
  const userState = BigInt(inputs.userState);
  const gistRootFromInputs = BigInt(inputs.gistRoot);

  const abi = [
    "function getGISTProof(uint256 id) view returns (uint256 root, bool existence, uint256[64] siblings, uint256 index, uint256 value, bool auxExistence, uint256 auxIndex, uint256 auxValue)"
  ];

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const contract = new ethers.Contract(stateContractAddress, abi, provider);

  const [
    root,
    existence,
    siblings,
    index,
    value,
    auxExistence,
    auxIndex,
    auxValue
  ] = await contract.getGISTProof(userGenesisID);

  const valueMatchesUserState = BigInt(value.toString()) === userState;
  const rootMatchesInputs = BigInt(root.toString()) === gistRootFromInputs;

  console.log(JSON.stringify({
    rpcHost: new URL(rpcUrl).host,
    stateContractAddress,
    userGenesisID: userGenesisID.toString(),
    userStateDecimal: userState.toString(),
    userStateHex: toHex32(userState),
    gistRootFromInputs: gistRootFromInputs.toString(),
    gistRootFromInputsHex: toHex32(gistRootFromInputs),
    contractRoot: root.toString(),
    contractRootHex: toHex32(root),
    rootMatchesInputs,
    existence,
    contractValue: value.toString(),
    contractValueHex: toHex32(value),
    valueMatchesUserState,
    index: index.toString(),
    auxExistence,
    auxIndex: auxIndex.toString(),
    auxValue: auxValue.toString(),
    siblingsLength: siblings.length,
    nonZeroSiblings: nonZeroCount(siblings)
  }, null, 2));

  if (!existence) {
    console.log("\nDIAGNOSIS: HOLDER_NOT_INCLUDED_IN_GIST");
    console.log("El State Contract devuelve existence=false para el holder userGenesisID.");
    console.log("SigV2OnChain no puede probar userGenesisID -> userState con este GIST.");
    console.log("Hace falta state transition del holder o manejo genesis exacto del SDK oficial.");
    return;
  }

  if (!valueMatchesUserState) {
    console.log("\nDIAGNOSIS: HOLDER_STATE_MISMATCH");
    console.log("El holder existe en GIST, pero el state on-chain no coincide con el userState mobile.");
    console.log("Hay que sincronizar/transitar el state correcto.");
    return;
  }

  console.log("\nDIAGNOSIS: HOLDER_GIST_INCLUDED_AND_MATCHES_USER_STATE");
  console.log("El GIST on-chain sí contiene userGenesisID -> userState.");
  console.log("Si el preflight sigue fallando, el bug está en la validación local del MTP.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
