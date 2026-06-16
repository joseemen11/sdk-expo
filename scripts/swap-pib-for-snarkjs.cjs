const fs = require("fs");

const inputPath = "debug/mobile-proof.json";
const outputPath = "debug/mobile-proof-snarkjs-pib-swap.json";

const proof = JSON.parse(fs.readFileSync(inputPath, "utf8"));

if (!proof.pi_b || !Array.isArray(proof.pi_b) || proof.pi_b.length < 2) {
  throw new Error("Invalid proof.pi_b shape");
}

proof.pi_b = [
  [proof.pi_b[0][1], proof.pi_b[0][0]],
  [proof.pi_b[1][1], proof.pi_b[1][0]],
  proof.pi_b[2]
];

fs.writeFileSync(outputPath, JSON.stringify(proof, null, 2), "utf8");

console.log("OK");
console.log(`Created: ${outputPath}`);
