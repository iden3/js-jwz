import { sha256 } from 'cross-sha256';
import { fromBigEndian, fromLittleEndian } from './core/util';
import * as circom from 'circomlibjs';
// Q is the order of the integer field (Zq) that fits inside the SNARK.
export const qString =
  '21888242871839275222246405745257275088548364400416034343698204186575808495617';
// console.log(circom);

export async function hash(message: Uint8Array): Promise<bigint> {
  // 1. sha256 hash

  const hashBytes = Uint8Array.from(new sha256().update(message).digest());
  console.log();
  // [34 50 246 35 105 128 246 37 210 89 55 178 228 49 37 189 28 88 148 161 174 30 41 25 134 251 16 226 254 113 40 161]

  // 2. swap hash before hashing
  const bi = fromBigEndian(hashBytes.reverse());
  console.log(bi);
  //15468677989380262565338453565485024441368986398242953448530041073672859494561

  let m = BigInt(0);
  if (checkBigIntInField(bi)) {
    m = bi;
  } else {
    m = bi % BigInt(qString);
  }
  console.log(m);
  //15468677989380262565338453565485024441368986398242953448530041073672859494561

  const poseidon = await circom.buildPoseidon();
  const bytes = await poseidon([m]);
  console.log(bytes);

  return fromBigEndian(bytes);
}

// checkBigIntInField checks if given *big.Int fits in a Field Q element
export function checkBigIntInField(a: bigint): boolean {
  return a < BigInt(qString);
}
