import { hash } from '../src/hash';
import * as circom from 'circomlibjs';
import { fromBigEndian } from '../src/core/util';

// test('hash', async () => {
//   const h = await hash(Uint8Array.from([1, 2]));

//   expect(h).toEqual(
//     BigInt(
//       '2075790386255975908302404091086184911566540917451248410360078182271861587231',
//     ),
//   );
// });

test('poseidon', async () => {
  const poseidon = await circom.buildPoseidon();
  const bytes = await poseidon([
    BigInt(
      '2075790386255975908302404091086184911566540917451248410360078182271861587231',
    ),
  ]);
  console.log(bytes);
  console.log(fromBigEndian(bytes));
  console.log(fromBigEndian(bytes));
  // expect(h).toEqual(
  //   BigInt(
  //     '2075790386255975908302404091086184911566540917451248410360078182271861587231',
  //   ),
  // );
});
