import { Id } from '@iden3/js-iden3-core';
import { ProvingMethod, ProvingMethodAlg, ZKProof } from './proving';
import { AuthV3Circuit, AuthV3_8_32Circuit, Groth16, prove, verify } from './common';
import { Hash } from '@iden3/js-merkletree';
import { getCurveFromName } from 'ffjavascript';

// AuthV3PubSignals auth.circom public signals
export interface AuthV3PubSignals {
  userID: Id;
  challenge: bigint;
  GISTRoot: Hash;
}

export const AuthV3Groth16Alg = new ProvingMethodAlg(Groth16, AuthV3Circuit);
export const AuthV3_8_32Groth16Alg = new ProvingMethodAlg(Groth16, AuthV3_8_32Circuit);

// ProvingMethodGroth16AuthV3 instance for Groth16 proving method with an authV3 circuit
export class ProvingMethodGroth16AuthV3 implements ProvingMethod {
  private static readonly curveName = 'bn128';

  constructor(public readonly methodAlg: ProvingMethodAlg) {}

  get alg(): string {
    return this.methodAlg.alg;
  }

  get circuitId(): string {
    return this.methodAlg.circuitId;
  }

  async verify(
    messageHash: Uint8Array,
    proof: ZKProof,
    verificationKey: Uint8Array
  ): Promise<boolean> {
    return verify<AuthV3PubSignals>(messageHash, proof, verificationKey, this.unmarshall);
  }

  async prove(inputs: Uint8Array, provingKey: Uint8Array, wasm: Uint8Array): Promise<ZKProof> {
    const zkProof = await prove(inputs, provingKey, wasm);
    await this.terminateCurve();
    return zkProof;
  }

  private async terminateCurve(): Promise<void> {
    const curve = await getCurveFromName(ProvingMethodGroth16AuthV3.curveName);
    curve.terminate();
  }

  unmarshall(pubSignals: string[]): AuthV3PubSignals {
    const len = 3;

    if (pubSignals.length !== len) {
      throw new Error(`invalid number of Output values expected ${len} got ${pubSignals.length}`);
    }

    return {
      userID: Id.fromBigInt(BigInt(pubSignals[0])),
      challenge: BigInt(pubSignals[1]),
      GISTRoot: Hash.fromString(pubSignals[2])
    };
  }
}

export const provingMethodGroth16AuthV3Instance: ProvingMethod = new ProvingMethodGroth16AuthV3(
  new ProvingMethodAlg(Groth16, AuthV3Circuit)
);

export const provingMethodGroth16AuthV3_8_32Instance: ProvingMethod =
  new ProvingMethodGroth16AuthV3(new ProvingMethodAlg(Groth16, AuthV3_8_32Circuit));
