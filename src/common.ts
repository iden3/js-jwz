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

const Fp2 = bn254.fields.Fp2;
const Fp12 = bn254.fields.Fp12;

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

const [G1PP, G2PP] = [bn254.G1.ProjectivePoint, bn254.G2.ProjectivePoint];

const toG1 = ([x, y]: string[]) => G1PP.fromAffine({ x: BigInt(x), y: BigInt(y) });

const toG2 = ([[x0, y0], [x1, y1]]: string[][]) => {
  return G2PP.fromAffine({
    x: Fp2.fromBigTuple([BigInt(x0), BigInt(y0)]),
    y: Fp2.fromBigTuple([BigInt(x1), BigInt(y1)])
  });
};

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
  const { proof, pub_signals } = zkp;

  if (pub_signals.length + 1 !== vk.IC.length) {
    throw new Error(
      `Invalid number of public signals, expected ${vk.IC.length - 1} but got ${pub_signals.length}`
    );
  }

  let cpub = G1PP.ZERO;

  for (let i = 0; i < pub_signals.length; i++) {
    // check input inside field
    if (BigInt(pub_signals[i]) < ZERO_BIGINT || BigInt(pub_signals[i]) >= bn254.G1.CURVE.n) {
      throw new Error(`Input value is not in the field ${bn254.G1.CURVE.n}`);
    }
    // Skip multiplication by 0 since it contributes nothing to the sum
    if (BigInt(pub_signals[i]) !== ZERO_BIGINT) {
      const [x, y] = vk.IC[i + 1].map(BigInt);
      cpub = cpub.add(G1PP.fromAffine({ x, y }).multiply(BigInt(pub_signals[i])));
    }
  }
  cpub = cpub.add(toG1(vk.IC[0]));

  const newRes = bn254.pairingBatch([
    { g1: toG1(proof.pi_a).negate(), g2: toG2(proof.pi_b) },
    { g1: cpub, g2: toG2(vk.vk_gamma_2) },
    { g1: toG1(proof.pi_c), g2: toG2(vk.vk_delta_2) },
    { g1: toG1(vk.vk_alpha_1), g2: toG2(vk.vk_beta_2) }
  ]);

  return Fp12.eql(newRes, Fp12.ONE);
}
