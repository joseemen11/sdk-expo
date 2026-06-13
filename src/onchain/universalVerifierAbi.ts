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
    outputs: [
      {
        name: "zkpRequest",
        type: "tuple",
        components: [
          { name: "metadata", type: "string" },
          { name: "validator", type: "address" },
          { name: "data", type: "bytes" }
        ]
      }
    ]
  },
  {
    type: "function",
    name: "requestIdExists",
    stateMutability: "view",
    inputs: [{ name: "requestId", type: "uint64" }],
    outputs: [{ name: "", type: "bool" }]
  },
  {
    type: "function",
    name: "isZKPRequestEnabled",
    stateMutability: "view",
    inputs: [{ name: "requestId", type: "uint64" }],
    outputs: [{ name: "", type: "bool" }]
  },
  {
    type: "function",
    name: "getRequestOwner",
    stateMutability: "view",
    inputs: [{ name: "requestId", type: "uint64" }],
    outputs: [{ name: "", type: "address" }]
  },
  {
    type: "function",
    name: "owner",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }]
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
