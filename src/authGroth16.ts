import { ProvingMethod, ProvingMethodAlg, ZKProof } from './proving';
import { Id } from '@iden3/js-iden3-core';
import { AuthCircuit, Groth16, prove, verify } from './common';

// AuthPubSignals auth.circom public signals
interface AuthPubSignals {
  challenge: bigint;
  userState: bigint;
  userId: Id;
}

// ProvingMethodGroth16Auth defines proofs family and specific circuit
class ProvingMethodGroth16Auth implements ProvingMethod {
  constructor(public readonly methodAlg: ProvingMethodAlg) {}

  get alg(): string {
    return this.methodAlg.alg;
  }

  get circuitId(): string {
    return this.methodAlg.circuitId;
  }

  unmarshall(pubsignals: string[]): AuthPubSignals {
    const outputs: AuthPubSignals = {} as AuthPubSignals;
    if (pubsignals.length != 3) {
      throw new Error(`invalid number of Output values expected ${3} got ${pubsignals.length}`);
    }
    outputs.challenge = BigInt(pubsignals[0]);
    outputs.userState = BigInt(pubsignals[1]);
    outputs.userId = Id.fromBigInt(BigInt(pubsignals[2]));

    return outputs;
  }

  async verify(
    messageHash: Uint8Array,
    proof: ZKProof,
    verificationKey: Uint8Array
  ): Promise<boolean> {
    return verify<AuthPubSignals>(messageHash, proof, verificationKey, this.unmarshall);
  }

  prove(inputs: Uint8Array, provingKey: Uint8Array, wasm: Uint8Array): Promise<ZKProof> {
    return prove(inputs, provingKey, wasm);
  }
}

export const provingMethodGroth16AuthInstance: ProvingMethod = new ProvingMethodGroth16Auth(
  new ProvingMethodAlg(Groth16, AuthCircuit)
);
