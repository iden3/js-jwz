import { Id } from './core/id';
import { fromLittleEndian } from './core/util';
import { ProvingMethod, registerProvingMethod, ZKProof } from './proving';
import * as snarkjs from 'snarkjs';
import * as wc from './witness/witness_calculator';
import { Core } from './core/core';

const groth16 = 'groth16';
const authCircuit = 'auth';

// AuthPubSignals auth.circom public signals
interface AuthPubSignals {
  challenge: bigint;
  userState: bigint;
  userId: Id;
}
async function unmarshall(pubsignals: string[]): Promise<AuthPubSignals> {
  const outputs: AuthPubSignals = {} as AuthPubSignals;
  if (pubsignals.length !== 3) {
    throw new Error(
      `invalid number of Output values expected 3 got ${pubsignals.length}`,
    );
  }
  outputs.challenge = BigInt(pubsignals[0]);
  outputs.userState = BigInt(pubsignals[1]);

  const bytes: Uint8Array = Core.intToBytes(BigInt(pubsignals[2]));
  outputs.userId = Id.idFromBytes(bytes);
  return outputs;
}

// ProvingMethodGroth16Auth defines proofs family and specific circuit
class ProvingMethodGroth16Auth implements ProvingMethod {
  constructor(public readonly alg: string, public readonly circuitId: string) {}

  async verify(
    messageHash: Uint8Array,
    proof: ZKProof,
    verificationKey: Uint8Array,
  ): Promise<boolean> {
    const outputs: AuthPubSignals = await unmarshall(proof.pub_signals);

    if (outputs.challenge !== fromLittleEndian(messageHash)) {
      console.error('challenge is not equal to message hash');
      return false;
    }
    return await snarkjs.groth16.verify(
      JSON.parse(Buffer.from(verificationKey).toString()),
      proof.pub_signals,
      proof.proof_data,
    );
  }

  async prove(
    inputs: Uint8Array,
    provingKey: Uint8Array,
    wasm: Uint8Array,
  ): Promise<ZKProof> {
    const witnessCalculator = await wc.default(wasm);

    const jsonString = Buffer.from(inputs).toString('utf8');

    const parsedData = JSON.parse(jsonString);
    const wtnsBytes: Uint8Array = await witnessCalculator.calculateWTNSBin(
      parsedData,
      0,
    );

    const { proof, publicSignals } = await snarkjs.groth16.prove(
      provingKey,
      wtnsBytes,
    );

    return {
      proof_data: proof,
      pub_signals: publicSignals,
    };
  }
}

export const provingMethodGroth16AuthInstance: ProvingMethod =
  new ProvingMethodGroth16Auth(groth16, authCircuit);

registerProvingMethod(
  provingMethodGroth16AuthInstance.alg,
  () => provingMethodGroth16AuthInstance,
);
