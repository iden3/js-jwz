import { hash } from '../src/hash';
import * as circom from 'circomlibjs';

test('hash', async () => {

  let utf8Encode = new TextEncoder();
  let arr =  utf8Encode.encode("message")

  expect(await hash(arr)).toEqual(
    BigInt(
      '12195879903067908640854440056941289904003404799313352286287749481941648225513',
    ),
  );
});

test('poseidon', async () => {
  const poseidon = await circom.poseidon;
  let utf8Encode = new TextEncoder();
  let arr =  utf8Encode.encode("message")
  let hex  = Buffer.from(arr).toString('hex');

  let  bigIntToHash =  BigInt(
    "0x"+ hex,
  )
  console.log("to hash:", bigIntToHash.toString())
  const bi = await poseidon([
     bigIntToHash
  ]);
  console.log(bi)
  expect(BigInt(bi).toString() == "16076885786305451396952367807583087877643965039481491647404584414044042908412")
});
