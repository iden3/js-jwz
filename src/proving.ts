export interface ZKProof {
  proof: ProofData;
  pub_signals: string[];
}
export interface ProofData {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
}

export class ProvingMethodAlg {
  constructor(public readonly alg: string, public readonly circuitId: string) {}

  toString(): string {
    return `${this.alg}:${this.circuitId}`;
  }
}

const provingMethods = new Map<string, () => ProvingMethod>(); // map[string]func() ProvingMethod{}

// ProvingMethod can be used add new methods for signing or verifying tokens.
export interface ProvingMethod {
  // Returns true if proof is valid
  verify(messageHash: Uint8Array, proof: ZKProof, verificationKey: Uint8Array): Promise<boolean>;
  // Returns proof or error
  prove(inputs: Uint8Array, provingKey: Uint8Array, wasm: Uint8Array): Promise<ZKProof>;

  readonly methodAlg: ProvingMethodAlg;

  readonly alg: string;
  // Returns the alg identifier for this method (example: 'AUTH-GROTH-16')
  readonly circuitId: string;
}

// RegisterProvingMethod registers the "alg" name and a factory function for proving method.
// This is typically done during init() in the method's implementation
export function registerProvingMethod(
  alg: ProvingMethodAlg,
  f: () => ProvingMethod
): Promise<void> {
  return new Promise((res) => {
    provingMethods.set(alg.toString(), f);
    res();
  });
}

// GetProvingMethod retrieves a proving method from an "alg" string
export function getProvingMethod(alg: ProvingMethodAlg): Promise<ProvingMethod> {
  return new Promise((res, rej) => {
    const func = provingMethods.get(alg.toString());
    if (func) {
      const method: ProvingMethod = func();
      res(method);
    } else {
      rej('unknown alg');
    }
  });
}

export function getAlgorithms(): Promise<string[]> {
  return Promise.resolve(Array.from(provingMethods.keys()).map((k) => k.split(':')[0]));
}

// ProofInputsPreparerHandlerFunc prepares inputs using hash message and circuit id
export type ProofInputsPreparerHandlerFunc = (
  hash: Uint8Array,
  circuitId: string
) => Promise<Uint8Array>;

// Prepare function is responsible to call provided handler for inputs preparation
export function prepare(
  f: ProofInputsPreparerHandlerFunc,
  hash: Uint8Array,
  circuitId: string
): Promise<Uint8Array> {
  return f(hash, circuitId);
}
