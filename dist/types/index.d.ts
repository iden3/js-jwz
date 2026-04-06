import { hash } from './hash';
import { Token, Header } from './jwz';
import { getProvingMethod, ProvingMethodAlg, registerProvingMethod, ProofInputsPreparerHandlerFunc, ProvingMethod, ZKProof, ProofData, DynamicProofInputsPreparerHandlerFunc } from './proving';
import { verifyGroth16Proof, Groth16VerificationKey } from './common';
import { witnessBuilder } from './witness_calculator';
declare const proving: {
    registerProvingMethod: typeof registerProvingMethod;
    getProvingMethod: typeof getProvingMethod;
    provingMethodGroth16AuthV2Instance: ProvingMethod;
    provingMethodGroth16AuthV3Instance: ProvingMethod;
    provingMethodGroth16AuthV3_8_32Instance: ProvingMethod;
};
export { proving, ProofInputsPreparerHandlerFunc, DynamicProofInputsPreparerHandlerFunc, ProvingMethod, ProvingMethodAlg, Token, hash, ZKProof, ProofData, Header, verifyGroth16Proof, Groth16VerificationKey, witnessBuilder };
//# sourceMappingURL=index.d.ts.map