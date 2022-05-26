import { Id } from './core/id';
import { fromLittleEndian } from './core/util';
import { ProvingMethod, registerProvingMethod, ZKProof } from './proving';
import * as snarkjs from 'snarkjs';
import { witnessBuilder } from './witness/witness_calculator';

const groth16 = 'groth16';
const authCircuit = 'auth';

// hash
// AuthPubSignals auth.circom public signals
interface AuthPubSignals {
  challenge: bigint;
  userState: unknown; //*merkletree.Hash `json:"userState"`
  userID: Id;
}

// ProvingMethodGroth16Auth defines proofs family and specific circuit
class ProvingMethodGroth16Auth implements ProvingMethod {
  constructor(public readonly alg: string, public readonly circuitId: string) {}

  // Verify performs groth16 proof verification and checks equality of message hash and proven challenge public signals
  // func (m *ProvingMethodGroth16Auth) Verify(messageHash []byte, proof *types.ZKProof, verificationKey []byte) error {

  // 	var outputs circuits.AuthPubSignals
  // 	pubBytes, err := json.Marshal(proof.PubSignals)
  // 	if err != nil {
  // 		return err
  // 	}

  // 	err = outputs.PubSignalsUnmarshal(pubBytes)
  // 	if err != nil {
  // 		return err
  // 	}

  // 	if outputs.Challenge.Cmp(new(big.Int).SetBytes(messageHash)) != 0 {
  // 		return errors.New("challenge is not equal to message hash")
  // 	}

  // 	return verifier.VerifyGroth16(*proof, verificationKey)
  // }

  verify(
    messageHash: Uint8Array,
    proof: ZKProof,
    verificationKey: Uint8Array,
  ): boolean {
    let outputs: AuthPubSignals = {};
    // TODO: AuthPubSignals
    // pubBytes, err := json.Marshal(proof.pubSignals)
    // if err != nil {
    // 	return err
    // }

    // err = outputs.PubSignalsUnmarshal(pubBytes)
    // if err != nil {
    // 	return err
    // }

    if (outputs.challenge !== fromLittleEndian(messageHash)) {
      console.error('challenge is not equal to message hash');
      return false;
    }

    return await snarkjs.groth16.verify(
      verificationKey,
      proof.pub_signals,
      proof.proof_data,
    );
  }

  // func (m *ProvingMethodGroth16Auth) Prove(inputs, provingKey, wasm []byte) (*types.ZKProof, error) {

  // 	calc, err := witness.NewCircom2WitnessCalculator(wasm, true)
  // 	if err != nil {
  // 		return nil, err
  // 	}

  // 	parsedInputs, err := witness.ParseInputs(inputs)
  // 	if err != nil {
  // 		return nil, err
  // 	}

  // 	wtnsBytes, err := calc.CalculateWTNSBin(parsedInputs, true)
  // 	if err != nil {
  // 		return nil, err
  // 	}
  // 	return prover.Groth16Prover(provingKey, wtnsBytes)

  // }
  // Prove generates proof using auth circuit and groth16 alg, checks that proven message hash is set as a part of circuit specific inputs
  async prove(
    inputs: Uint8Array,
    provingKey: Uint8Array,
    wasm: Uint8Array,
  ): ZKProof {
    const calc = {} as any; // witness.NewCircom2WitnessCalculator(wasm, true)
    const witnessCalculator = await witnessBuilder(inputs, true);
    const buff: Uint8Array = await witnessCalculator.calculateWTNSBin(
      inputs,
      0,
    );
    return null;
  }
}

//TODO: move this out
const provingMethodGroth16AuthInstance: ProvingMethod =
  new ProvingMethodGroth16Auth(groth16, authCircuit);

function init(): void {
  registerProvingMethod(
    provingMethodGroth16AuthInstance.alg,
    () => provingMethodGroth16AuthInstance,
  );
}
