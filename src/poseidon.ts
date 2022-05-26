// import { bigInt, bn128 } from 'snarkjs';

// const F = bn128.Fr;
// import { poseidon } from 'circomlib';

// export function hash(arr) {
//   const poseidonHash = poseidon.createHash(6, 8, 57);
//   return poseidonHash(arr);
// }

// export function multiHash(arr) {
//   // TODO check bigints inside finite field

//   let r = bigInt(0);
//   for (let i = 0; i < arr.length; i += 5) {
//     const fiveElems = [];
//     for (let j = 0; j < 5; j++) {
//       if (i + j < arr.length) {
//         fiveElems.push(arr[i + j]);
//       } else {
//         fiveElems.push(bigInt(0));
//       }
//     }
//     const ph = hash(fiveElems);
//     r = F.add(r, ph);
//   }
//   return F.affine(r);
// }

// export function hashBuffer(msgBuff) {
//   const n = 31;
//   const msgArray = [];
//   const fullParts = Math.floor(msgBuff.length / n);
//   for (let i = 0; i < fullParts; i++) {
//     const v = bigInt.leBuff2int(msgBuff.slice(n * i, n * (i + 1)));
//     msgArray.push(v);
//   }
//   if (msgBuff.length % n !== 0) {
//     const v = bigInt.leBuff2int(msgBuff.slice(fullParts * n));
//     msgArray.push(v);
//   }
//   return multiHash(msgArray);
// }
