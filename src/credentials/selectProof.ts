import { isRecord } from "./diagnostics";

const MTP_PROOF_TYPE = "Iden3SparseMerkleTreeProof";

export function selectMtpProofCredential<TCredential>(credential: TCredential): TCredential {
  if (!isRecord(credential)) {
    throw new Error("Credential must be a JSON object.");
  }

  const proof = credential.proof;
  const proofs = Array.isArray(proof) ? proof : proof ? [proof] : [];
  const mtpProof = proofs.find((candidate) => isRecord(candidate) && candidate.type === MTP_PROOF_TYPE);

  if (!mtpProof) {
    throw new Error("Credential does not contain an MTP proof.");
  }

  return {
    ...credential,
    proof: mtpProof
  } as TCredential;
}
