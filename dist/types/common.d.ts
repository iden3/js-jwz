import { ZKProof } from './proving';
export declare const Groth16 = "groth16";
export declare const AuthCircuit = "auth";
export declare const AuthV2Circuit = "authV2";
export declare const AuthV3Circuit = "authV3";
export declare const AuthV3_8_32Circuit = "authV3-8-32";
export type Groth16VerificationKey = {
    protocol: 'groth16';
    curve: 'bn128';
    nPublic: number;
    vk_alpha_1: [string, string, string];
    vk_beta_2: [[string, string], [string, string], [string, string]];
    vk_gamma_2: [[string, string], [string, string], [string, string]];
    vk_delta_2: [[string, string], [string, string], [string, string]];
    vk_alphabeta_12: [
        [
            [string, string],
            [string, string],
            [string, string]
        ],
        [
            [string, string],
            [string, string],
            [string, string]
        ]
    ];
    IC: [string, string, string][];
};
export declare function prove(inputs: Uint8Array, provingKey: Uint8Array, wasm: Uint8Array): Promise<ZKProof>;
export declare function verify<T extends {
    challenge: bigint;
}>(messageHash: Uint8Array, proof: ZKProof, verificationKey: Uint8Array, unmarshall: (pubSignals: string[]) => T): Promise<boolean>;
export declare function verifyGroth16Proof(zkp: ZKProof, vk: Groth16VerificationKey): boolean;
//# sourceMappingURL=common.d.ts.map