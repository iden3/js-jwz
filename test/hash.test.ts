import { poseidon } from '@iden3/js-crypto';
import { hash } from '../src/hash';

test('hash', () => {
  const utf8Encode = new TextEncoder();
  const arr = utf8Encode.encode('message');

  const res = hash(arr);

  expect(res.toString()).toBe(
    '12195879903067908640854440056941289904003404799313352286287749481941648225513'
  );
});
test('hash long message', () => {
  const utf8Encode = new TextEncoder();
  const arr = utf8Encode.encode(
    '{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"6568187306293073175114267504711682812904598368490904573742495126063294481938","challengeSignatureR8x":"15230565441506590379169832995887068998322005265009046474267743823535028195613","challengeSignatureR8y":"10769958837943955028152112183244447895061604149794975067459918696631541903296","challengeSignatureS":"421650140447062113811542806382702329042840096310563827636625110300562791229","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userID":"379949150130214723420589610911161895495647789006649785264738141299135414272","userRevTreeRoot":"0","userRootsTreeRoot":"0","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313"}'
  );

  const res = hash(arr);

  expect(res.toString()).toBe(
    '3741385570005605084300493775652159969493539073276486448913383306368831791102'
  );
});

test('poseidon', () => {
  const utf8Encode = new TextEncoder();
  const arr = utf8Encode.encode('message');
  const hex = Buffer.from(arr).toString('hex');
  const bigIntToHash = BigInt('0x' + hex);

  const bi = poseidon.hash([bigIntToHash]);
  expect(
    bi.toString() == '16076885786305451396952367807583087877643965039481491647404584414044042908412'
  );
});
