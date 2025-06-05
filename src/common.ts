import { ZKProof } from './proving';
import { witnessBuilder } from './witness_calculator';
import { groth16 } from 'snarkjs';
import { fromBigEndian } from '@iden3/js-iden3-core';
import { bn254 } from '@noble/curves/bn254';

export const Groth16 = 'groth16';
export const AuthCircuit = 'auth';
export const AuthV2Circuit = 'authV2';
const textDecoder = new TextDecoder();
const ZERO_BIGINT = BigInt(0);
const ONE_BIGINT = BigInt(1);

export type Groth16VerificationKey = {
  protocol: 'groth16';
  curve: 'bn128';
  nPublic: number;
  vk_alpha_1: [string, string, string];
  vk_beta_2: [[string, string], [string, string], [string, string]];
  vk_gamma_2: [[string, string], [string, string], [string, string]];
  vk_delta_2: [[string, string], [string, string], [string, string]];
  vk_alphabeta_12: [
    [[string, string], [string, string], [string, string]],
    [[string, string], [string, string], [string, string]]
  ];
  IC: [string, string, string][];
};

export async function prove(
  inputs: Uint8Array,
  provingKey: Uint8Array,
  wasm: Uint8Array
): Promise<ZKProof> {
  const witnessCalculator = await witnessBuilder(wasm);

  const jsonString = new TextDecoder().decode(inputs);

  const parsedData = JSON.parse(jsonString);
  const wtnsBytes: Uint8Array = await witnessCalculator.calculateWTNSBin(parsedData, 0);

  const { proof, publicSignals } = await groth16.prove(provingKey, wtnsBytes);

  return {
    proof: proof,
    pub_signals: publicSignals
  };
}

export async function verify<T extends { challenge: bigint }>(
  messageHash: Uint8Array,
  proof: ZKProof,
  verificationKey: Uint8Array,
  unmarshall: (pubSignals: string[]) => T
): Promise<boolean> {
  const outputs: T = unmarshall(proof.pub_signals);
  if (outputs.challenge !== fromBigEndian(messageHash)) {
    throw new Error('challenge is not equal to message hash');
  }

  const vk: Groth16VerificationKey = JSON.parse(textDecoder.decode(verificationKey));

  return verifyGroth16Proof(proof, vk);
}

export function verifyGroth16Proof(zkp: ZKProof, vk: Groth16VerificationKey): boolean {
  if (!vk.IC) {
    throw new Error(`verification file doesn't exist for circuit`);
  }

  if (zkp.pub_signals.length + 1 !== vk.IC.length) {
    throw new Error(
      `Invalid number of public signals, expected ${vk.IC.length - 1} but got ${
        zkp.pub_signals.length
      }`
    );
  }
  const [G1PP, G2PP] = [bn254.G1.ProjectivePoint, bn254.G2.ProjectivePoint];
  const toG1 = ([x, y]: string[]) => G1PP.fromAffine({ x: BigInt(x), y: BigInt(y) });

  const toG2 = ([[x0, y0], [x1, y1]]: string[][]) => {
    const Fp2 = bn254.fields.Fp2;
    return G2PP.fromAffine({
      x: Fp2.fromBigTuple([BigInt(x0), BigInt(y0)]),
      y: Fp2.fromBigTuple([BigInt(x1), BigInt(y1)])
    });
  };

  const { proof, pub_signals } = zkp;
  let vkX = G1PP.ZERO;

  for (let i = 0; i < pub_signals.length; i++) {
    // check input inside field
    if (BigInt(pub_signals[i]) >= bn254.G1.CURVE.n) {
      throw new Error(`Input value is not in the fields`);
    }
    // Skip multiplication by 0 since it contributes nothing to the sum
    if (BigInt(pub_signals[i]) !== 0n) {
      const [x, y] = vk.IC[i + 1].map(BigInt);
      vkX = vkX.add(G1PP.fromAffine({ x, y }).multiply(BigInt(pub_signals[i])));
    }
  }
  vkX = vkX.add(toG1(vk.IC[0]));

  const piAG1 = toG1(proof.pi_a);

  const alphaG1Neg = toG1(vk.vk_alpha_1).negate();

  const negVkx = vkX.negate();

  const piCNeg = toG1(proof.pi_c).negate();

  const g1 = [piAG1, alphaG1Neg, negVkx, piCNeg];
  const g2 = [proof.pi_b, vk.vk_beta_2, vk.vk_gamma_2, vk.vk_delta_2].map(toG2);

  const { c0, c1 } = bn254.pairingBatch(g1.map((g, i) => ({ g1: g, g2: g2[i] })));

  return (
    c0.c0.c0 === ONE_BIGINT &&
    c0.c0.c1 === ZERO_BIGINT &&
    c0.c1.c0 === ZERO_BIGINT &&
    c0.c1.c1 === ZERO_BIGINT &&
    c0.c2.c0 === ZERO_BIGINT &&
    c0.c2.c1 === ZERO_BIGINT &&
    c1.c0.c0 === ZERO_BIGINT &&
    c1.c0.c1 === ZERO_BIGINT &&
    c1.c1.c0 === ZERO_BIGINT &&
    c1.c1.c1 === ZERO_BIGINT &&
    c1.c2.c0 === ZERO_BIGINT &&
    c1.c2.c1 === ZERO_BIGINT
  );
}
