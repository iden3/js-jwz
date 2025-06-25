import { hash } from './hash';
import { Token, Header } from './jwz';
import { provingMethodGroth16AuthInstance } from './authGroth16';
import {
  getProvingMethod,
  ProofInputsPreparerHandlerFunc,
  ProvingMethod,
  ProvingMethodAlg,
  registerProvingMethod,
  ZKProof,
  ProofData
} from './proving';
import { provingMethodGroth16AuthV2Instance } from './authV2Groth16';
import { Groth16VerificationKey, verifyGroth16Proof } from './common';
import { witnessBuilder } from './witness_calculator';

registerProvingMethod(
  provingMethodGroth16AuthInstance.methodAlg,
  () => provingMethodGroth16AuthInstance
);

registerProvingMethod(
  provingMethodGroth16AuthV2Instance.methodAlg,
  () => provingMethodGroth16AuthV2Instance
);

const proving = {
  registerProvingMethod,
  getProvingMethod,
  provingMethodGroth16AuthInstance,
  provingMethodGroth16AuthV2Instance
};

export {
  proving,
  ProofInputsPreparerHandlerFunc,
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
