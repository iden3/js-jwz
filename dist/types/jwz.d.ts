import { ZKProof, ProvingMethod, ProofInputsPreparerHandlerFunc, DynamicProofInputsPreparerHandlerFunc } from './proving';
export declare enum Header {
    Type = "typ",
    Alg = "alg",
    CircuitId = "circuitId",
    Critical = "crit"
}
export interface IRawJSONWebZeroknowledge {
    payload: Uint8Array;
    protectedHeaders: Uint8Array;
    header: {
        [key: string]: unknown;
    };
    zkp: Uint8Array;
    sanitized(): Promise<Token>;
}
export declare class RawJSONWebZeroknowledge implements IRawJSONWebZeroknowledge {
    payload: Uint8Array;
    protectedHeaders: Uint8Array;
    header: {
        [key: string]: unknown;
    };
    zkp: Uint8Array;
    constructor(payload: Uint8Array, protectedHeaders: Uint8Array, header: {
        [key: string]: unknown;
    }, zkp: Uint8Array);
    sanitized(): Promise<Token>;
}
export declare class Token {
    readonly method: ProvingMethod;
    private readonly inputsPreparer?;
    alg: string;
    circuitId: string;
    private raw;
    zkProof: ZKProof;
    constructor(method: ProvingMethod, payload: string, inputsPreparer?: ProofInputsPreparerHandlerFunc | undefined);
    setHeader(key: string, value: unknown): void;
    getPayload(): string;
    private getDefaultHeaders;
    static parse(tokenStr: string): Promise<Token>;
    private static parseCompact;
    private static parseFull;
    prove(provingKey: Uint8Array, wasm: Uint8Array): Promise<string>;
    dynamicProve(dynamicProvingParams: {
        provingParams: {
            circuitId: string;
            provingKey: Uint8Array;
            wasm: Uint8Array;
        }[];
        inputsPreparerFn: DynamicProofInputsPreparerHandlerFunc | ProofInputsPreparerHandlerFunc;
    }): Promise<string>;
    compactSerialize(): string;
    fullSerialize(): string;
    getMessageHash(): Promise<Uint8Array>;
    verify(verificationKey: Uint8Array): Promise<boolean>;
    dynamicVerify(dynamicVerificationParams: {
        verificationKeysMap: {
            circuitId: string;
            verificationKey: Uint8Array;
        }[];
    }): Promise<boolean>;
    serializeHeaders(): string;
}
//# sourceMappingURL=jwz.d.ts.map