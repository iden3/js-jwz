import { provingMethodGroth16AuthV2Instance } from './authV2Groth16';
import {
  provingMethodGroth16AuthV3_8_32Instance,
  provingMethodGroth16AuthV3Instance
} from './authV3Groth16';
import { type Groth16VerificationKey, verifyGroth16Proof } from './common';
import { hash } from './hash';
import { Header, Token } from './jwz';
import {
  type DynamicProofInputsPreparerHandlerFunc,
  getProvingMethod,
  type ProofData,
  type ProofInputsPreparerHandlerFunc,
  type ProvingMethod,
  ProvingMethodAlg,
  registerProvingMethod,
  type ZKProof
} from './proving';
import { witnessBuilder } from './witness_calculator';

registerProvingMethod(
  provingMethodGroth16AuthV2Instance.methodAlg,
  () => provingMethodGroth16AuthV2Instance
);

registerProvingMethod(
  provingMethodGroth16AuthV3Instance.methodAlg,
  () => provingMethodGroth16AuthV3Instance
);

registerProvingMethod(
  provingMethodGroth16AuthV3_8_32Instance.methodAlg,
  () => provingMethodGroth16AuthV3_8_32Instance
);

const proving = {
  registerProvingMethod,
  getProvingMethod,
  provingMethodGroth16AuthV2Instance,
  provingMethodGroth16AuthV3Instance,
  provingMethodGroth16AuthV3_8_32Instance
};

export {
  type DynamicProofInputsPreparerHandlerFunc,
  type Groth16VerificationKey,
  Header,
  hash,
  type ProofData,
  type ProofInputsPreparerHandlerFunc,
  type ProvingMethod,
  ProvingMethodAlg,
  proving,
  Token,
  verifyGroth16Proof,
  witnessBuilder,
  type ZKProof
};
