import { sha256 } from 'cross-sha256';
import { fromBigEndian } from './core/util';
import * as circom from 'circomlibjs';

// Q is the order of the integer field (Zq) that fits inside the SNARK.
export const qString =
  '21888242871839275222246405745257275088548364400416034343698204186575808495617';

export async function hash(message: Uint8Array): Promise<bigint> {
  // 1. sha256 hash
  const hashBytes = Uint8Array.from(new sha256().update(message).digest());

  // 2. swap hash before hashing
  const bi = fromBigEndian(hashBytes.reverse());

  let m = BigInt(0);
  if (checkBigIntInField(bi)) {
    m = bi;
  } else {
    m = bi % BigInt(qString);
  }

  const poseidon = await circom.poseidon;
  const poseidonHash = await poseidon([m]);

  return poseidonHash;
}

// checkBigIntInField checks if given *big.Int fits in a Field Q element
export function checkBigIntInField(a: bigint): boolean {
  return a < BigInt(qString);
}
