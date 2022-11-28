import { hash } from './hash';
import { Token, Header } from './jwz';
import { provingMethodGroth16AuthInstance } from './authGroth16';
import {
  getProvingMethod,
  ProofInputsPreparerHandlerFunc,
  ProvingMethod,
  registerProvingMethod,
} from './proving';

registerProvingMethod(
  provingMethodGroth16AuthInstance.alg,
  () => provingMethodGroth16AuthInstance,
);

const proving = {
  registerProvingMethod,
  getProvingMethod,
  provingMethodGroth16AuthInstance,
};

export {
  proving,
  ProofInputsPreparerHandlerFunc,
  ProvingMethod,
  Token,
  hash,
  Header,
};
