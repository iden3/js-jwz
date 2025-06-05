import { Id } from '@iden3/js-iden3-core';
import { ProvingMethod, ProvingMethodAlg, ZKProof } from './proving';
import { AuthV2Circuit, Groth16, prove, verify } from './common';
import { Hash } from '@iden3/js-merkletree';
import { getCurveFromName } from 'ffjavascript';

// AuthV2PubSignals auth.circom public signals
export interface AuthV2PubSignals {
  userID: Id;
  challenge: bigint;
  GISTRoot: Hash;
}

export const AuthV2Groth16Alg = new ProvingMethodAlg(Groth16, AuthV2Circuit);

// ProvingMethodGroth16AuthV2 instance for Groth16 proving method with an authV2 circuit
export class ProvingMethodGroth16AuthV2 implements ProvingMethod {
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
    return verify<AuthV2PubSignals>(messageHash, proof, verificationKey, this.unmarshall);
  }

  async prove(inputs: Uint8Array, provingKey: Uint8Array, wasm: Uint8Array): Promise<ZKProof> {
    const zkProof = await prove(inputs, provingKey, wasm);
    await this.terminateCurve();
    return zkProof;
  }

  private async terminateCurve(): Promise<void> {
    const curve = await getCurveFromName(ProvingMethodGroth16AuthV2.curveName);
    curve.terminate();
  }

  unmarshall(pubSignals: string[]): AuthV2PubSignals {
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

export const provingMethodGroth16AuthV2Instance: ProvingMethod = new ProvingMethodGroth16AuthV2(
  new ProvingMethodAlg(Groth16, AuthV2Circuit)
);
