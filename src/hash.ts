import { fromBigEndian } from '@iden3/js-iden3-core';
import { poseidon } from '@iden3/js-crypto';
import { sha256 } from 'cross-sha256';

// Q is the order of the integer field (Zq) that fits inside the SNARK.
export const qString =
  '21888242871839275222246405745257275088548364400416034343698204186575808495617';

export function hash(message: Uint8Array): bigint {
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

  return poseidon.hash([m]);
}

// checkBigIntInField checks if given *big.Int fits in a Field Q element
export function checkBigIntInField(a: bigint): boolean {
  return a < BigInt(qString);
}
