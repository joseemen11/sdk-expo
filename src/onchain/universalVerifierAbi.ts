export const universalVerifierAbi = [
  {
    type: "function",
    name: "isProofVerified",
    stateMutability: "view",
    inputs: [
      { name: "sender", type: "address" },
      { name: "requestId", type: "uint64" }
    ],
    outputs: [{ name: "", type: "bool" }]
  },
  {
    type: "function",
    name: "getZKPRequest",
    stateMutability: "view",
    inputs: [{ name: "requestId", type: "uint64" }],
    outputs: [{ name: "", type: "tuple" }]
  },
  {
    type: "function",
    name: "submitZKPResponse",
    stateMutability: "nonpayable",
    inputs: [
      { name: "requestId", type: "uint64" },
      { name: "inputs", type: "uint256[]" },
      { name: "a", type: "uint256[2]" },
      { name: "b", type: "uint256[2][2]" },
      { name: "c", type: "uint256[2]" }
    ],
    outputs: []
  }
] as const;
