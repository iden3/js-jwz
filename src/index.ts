import { hash } from './hash';
import { Token } from './jwz';
import { provingMethodGroth16AuthInstance } from './authGroth16';
import {
  getProvingMethod,
  ProofInputsPreparerHandlerFunc,
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

export { proving, ProofInputsPreparerHandlerFunc, Token, hash };
