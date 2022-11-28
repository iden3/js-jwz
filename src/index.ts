import { hash } from './hash';
import { Token, Header } from './jwz';
import { provingMethodGroth16AuthInstance } from './authGroth16';
import {
  getProvingMethod,
  ProofInputsPreparerHandlerFunc,
  ProvingMethod,
  registerProvingMethod,
} from './proving';
import { provingMethodGroth16AuthV2Instance } from './authV2Groth16';

registerProvingMethod(
  provingMethodGroth16AuthInstance.methodAlg,
  () => provingMethodGroth16AuthInstance,
);

registerProvingMethod(
  provingMethodGroth16AuthV2Instance.methodAlg,
  () => provingMethodGroth16AuthInstance,
);

const proving = {
  registerProvingMethod,
  getProvingMethod,
  provingMethodGroth16AuthInstance,
  provingMethodGroth16AuthV2Instance,
};

export {
  proving,
  ProofInputsPreparerHandlerFunc,
  ProvingMethod,
  Token,
  hash,
  Header,
};
