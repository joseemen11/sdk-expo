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
    const proofTypes = proofs
      .filter(isRecord)
      .map((candidate) => candidate.type)
      .flatMap((type) => Array.isArray(type) ? type : [type])
      .filter((type): type is string => typeof type === "string" && type.length > 0);
    throw new Error(
      `No MTP proof in saved credential. Claim/hydration did not return a VC with Iden3SparseMerkleTreeProof. proofTypes: ${
        proofTypes.length > 0 ? proofTypes.join(", ") : "none"
      }`
    );
  }

  return {
    ...credential,
    proof: mtpProof
  } as TCredential;
}
