const fs = require("fs");

const inputPath = "sigv2-onchain-direct-verifier-debug.clean.json";
const j = JSON.parse(fs.readFileSync(inputPath, "utf8"));

const proof = {
  ...j.preparedProof.proof,
  protocol: "groth16",
  curve: "bn128"
};

const publicSignals = j.preparedProof.publicSignals;

fs.writeFileSync("proof.mobile.json", JSON.stringify(proof, null, 2));
fs.writeFileSync("public.mobile.json", JSON.stringify(publicSignals, null, 2));

console.log("proof.mobile.json creado");
console.log("public.mobile.json creado");
console.log("publicSignals:", publicSignals.length);
