const fs = require("fs");

function readPossiblyPowerShellEncodedJson(path) {
  const buffer = fs.readFileSync(path);

  let text;
  if (buffer[0] === 0xff && buffer[1] === 0xfe) {
    text = buffer.toString("utf16le");
  } else {
    text = buffer.toString("utf8");
  }

  text = text
    .replace(/^\uFEFF/, "")
    .replace(/\u0000/g, "")
    .replace(/\uFFFD/g, "")
    .trim();

  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");

  if (first === -1 || last === -1 || last <= first) {
    throw new Error(`No JSON object found in ${path}`);
  }

  const jsonText = text.slice(first, last + 1);
  return JSON.parse(jsonText);
}

const direct = readPossiblyPowerShellEncodedJson(
  "debug/sigv2-onchain-direct-verifier-debug.json"
);

const inputs = readPossiblyPowerShellEncodedJson(
  "debug/sigv2-onchain-circuit-inputs-debug.json"
);

fs.writeFileSync(
  "debug/sigv2-onchain-direct-verifier-debug.clean.json",
  JSON.stringify(direct, null, 2),
  "utf8"
);

fs.writeFileSync(
  "debug/sigv2-onchain-circuit-inputs-debug.clean.json",
  JSON.stringify(inputs, null, 2),
  "utf8"
);

const prepared = direct.preparedProof;

if (!prepared) {
  throw new Error("preparedProof not found in direct debug JSON");
}

if (!prepared.proof) {
  throw new Error("proof not found in preparedProof");
}

if (!Array.isArray(prepared.publicSignals)) {
  throw new Error("publicSignals not found or not array in preparedProof");
}

fs.writeFileSync(
  "debug/mobile-proof.json",
  JSON.stringify(prepared.proof, null, 2),
  "utf8"
);

fs.writeFileSync(
  "debug/mobile-public-signals.json",
  JSON.stringify(prepared.publicSignals, null, 2),
  "utf8"
);

console.log("OK");
console.log("Created:");
console.log("- debug/sigv2-onchain-direct-verifier-debug.clean.json");
console.log("- debug/sigv2-onchain-circuit-inputs-debug.clean.json");
console.log("- debug/mobile-proof.json");
console.log("- debug/mobile-public-signals.json");
console.log(`publicSignalsCount: ${prepared.publicSignals.length}`);
console.log(`circuitId: ${prepared.circuitId}`);
console.log(`requestId: ${prepared.request?.id}`);
