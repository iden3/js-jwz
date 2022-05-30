import { hash } from '../src/hash';
import * as circom from 'circomlibjs';

test('hash', async () => {
  let utf8Encode = new TextEncoder();
  let arr = utf8Encode.encode('message');

  expect(await hash(arr)).toEqual(
    BigInt(
      '12195879903067908640854440056941289904003404799313352286287749481941648225513',
    ),
  );
});

test('hash long message', async () => {
  let utf8Encode = new TextEncoder();
  let arr = utf8Encode.encode('message');

  let msgHex =
    '65794a68624763694f694a6e636d3930614445324969776959326c795933567064456c6b496a6f695958563061434973496d4e79615851694f6c736959326c795933567064456c6b496c3073496e523563434936496b705857694a392e62586c745a584e7a5957646c';

  const msgFromHEx = Uint8Array.from(Buffer.from(msgHex, 'hex'));

  let res = await hash(msgFromHEx);
  expect(res).toEqual(
    BigInt(
      '19054333970885023780123560936675456700861469068603321884718748961750930466794',
    ),
  );
});

test('poseidon', async () => {
  const poseidon = await circom.poseidon;
  let utf8Encode = new TextEncoder();
  let arr = utf8Encode.encode('message');
  let hex = Buffer.from(arr).toString('hex');

  let bigIntToHash = BigInt('0x' + hex);
  const bi = await poseidon([bigIntToHash]);
  expect(
    BigInt(bi).toString() ==
      '16076885786305451396952367807583087877643965039481491647404584414044042908412',
  );
});
