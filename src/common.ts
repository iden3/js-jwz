import { ZKProof } from './proving';
import { witnessBuilder } from './witness_calculator';
import { groth16 } from 'snarkjs';
import { fromBigEndian } from '@iden3/js-iden3-core';

export const Groth16 = 'groth16';
export const AuthCircuit = 'auth';
export const AuthV2Circuit = 'authV2';
const textDecoder = new TextDecoder();

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
  const result = await groth16.verify(
    JSON.parse(textDecoder.decode(verificationKey)),
    proof.pub_signals,
    proof.proof
  );
  return result;
}
