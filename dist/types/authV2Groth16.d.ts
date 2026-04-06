import { Id } from '@iden3/js-iden3-core';
import { ProvingMethod, ProvingMethodAlg, ZKProof } from './proving';
import { Hash } from '@iden3/js-merkletree';
export interface AuthV2PubSignals {
    userID: Id;
    challenge: bigint;
    GISTRoot: Hash;
}
export declare const AuthV2Groth16Alg: ProvingMethodAlg;
export declare class ProvingMethodGroth16AuthV2 implements ProvingMethod {
    readonly methodAlg: ProvingMethodAlg;
    private readonly opts?;
    private static readonly curveName;
    constructor(methodAlg: ProvingMethodAlg, opts?: {
        circuitSubVersions: string[];
    } | undefined);
    get alg(): string;
    get circuitId(): string;
    get supportedCircuits(): string[];
    verify(messageHash: Uint8Array, proof: ZKProof, verificationKey: Uint8Array): Promise<boolean>;
    prove(inputs: Uint8Array, provingKey: Uint8Array, wasm: Uint8Array): Promise<ZKProof>;
    private terminateCurve;
    unmarshall(pubSignals: string[]): AuthV2PubSignals;
}
export declare const provingMethodGroth16AuthV2Instance: ProvingMethod;
//# sourceMappingURL=authV2Groth16.d.ts.map