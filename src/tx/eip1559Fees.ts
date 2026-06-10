export interface Eip1559FeeSuggestion {
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
}

export function createEmptyEip1559FeeSuggestion(): Eip1559FeeSuggestion {
  return {};
}
