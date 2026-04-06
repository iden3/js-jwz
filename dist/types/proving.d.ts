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
export declare class ProvingMethodAlg {
    readonly alg: string;
    readonly circuitId: string;
    constructor(alg: string, circuitId: string);
    toString(): string;
}
export interface ProvingMethod {
    verify(messageHash: Uint8Array, proof: ZKProof, verificationKey: Uint8Array): Promise<boolean>;
    prove(inputs: Uint8Array, provingKey: Uint8Array, wasm: Uint8Array): Promise<ZKProof>;
    readonly methodAlg: ProvingMethodAlg;
    readonly alg: string;
    readonly circuitId: string;
    get supportedCircuits(): string[];
}
export declare function registerProvingMethod(alg: ProvingMethodAlg, f: () => ProvingMethod): Promise<void>;
export declare function getProvingMethod(alg: ProvingMethodAlg): Promise<ProvingMethod>;
export declare function getAlgorithms(): Promise<string[]>;
export type ProofInputsPreparerHandlerFunc = (hash: Uint8Array, circuitId: string) => Promise<Uint8Array>;
export type DynamicProofInputsPreparerHandlerFunc = (hash: Uint8Array, circuitId: string) => Promise<{
    inputs: Uint8Array;
    targetCircuitId: string;
}>;
//# sourceMappingURL=proving.d.ts.map