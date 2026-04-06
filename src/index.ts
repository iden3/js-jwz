import { hash } from './hash';
import { Token, Header } from './jwz';
import { getProvingMethod, ProvingMethodAlg, registerProvingMethod } from './proving';
import type {
  ProofInputsPreparerHandlerFunc,
  ProvingMethod,
  ZKProof,
  ProofData,
  DynamicProofInputsPreparerHandlerFunc
} from './proving';
import { provingMethodGroth16AuthV2Instance } from './authV2Groth16';
import { verifyGroth16Proof } from './common';
import type { Groth16VerificationKey } from './common';
import { witnessBuilder } from './witness_calculator';
import {
  provingMethodGroth16AuthV3Instance,
  provingMethodGroth16AuthV3_8_32Instance
} from './authV3Groth16';

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
  proving,
  ProofInputsPreparerHandlerFunc,
  DynamicProofInputsPreparerHandlerFunc,
  ProvingMethod,
  ProvingMethodAlg,
  Token,
  hash,
  ZKProof,
  ProofData,
  Header,
  verifyGroth16Proof,
  Groth16VerificationKey,
  witnessBuilder
};
