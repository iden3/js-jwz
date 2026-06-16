import { describe, expect, test } from 'vitest';
import { AuthV2Circuit, Groth16 } from '../src/common';
import { type ProofInputsPreparerHandlerFunc, proving } from '../src/index';
import { Token } from '../src/jwz';

// Browser-only smoke test: proving + verification must work in the browser
// (loaded via fetch since `fs` is not available in the browser environment).

const mock: ProofInputsPreparerHandlerFunc = (): Promise<Uint8Array> =>
  Promise.resolve(
    new TextEncoder().encode(
      `{"genesisID":"23148936466334350744548790012294489365207440754509988986684797708370051073","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6110517768249559238193477435454792024732173865488900270849624328650765691494","challengeSignatureR8x":"10923900855019966925146890192107445603460581432515833977084358496785417078889","challengeSignatureR8y":"16158862443157007045624936621448425746188316255879806600364391221203989186031","challengeSignatureS":"51416591880507739389339515804072924841765472826035808894700970942045022090","claimsTreeRoot":"8162166103065016664685834856644195001371303013149727027131225893397958846382","revTreeRoot":"0","rootsTreeRoot":"0","state":"8039964009611210398788855768060749920589777058607598891238307089541758339342","gistRoot":"1243904711429961858774220647610724273798918457991486031567244100767259239747","gistMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"1","gistMtpAuxHv":"1","gistMtpNoAux":"0"}`
    )
  );

const fetchBytes = async (path: string): Promise<Uint8Array> => {
  const res = await fetch(path);
  if (!res.ok) {
    throw new Error(`failed to fetch ${path}: ${res.status}`);
  }
  return new Uint8Array(await res.arrayBuffer());
};

describe('authV2Groth16 (browser)', () => {
  test('prove and verify in browser', async () => {
    const payload = 'mymessage';
    const token = new Token(proving.provingMethodGroth16AuthV2Instance, payload, mock);

    expect(token.alg).toEqual(Groth16);
    expect(token.circuitId).toEqual(AuthV2Circuit);

    const provingKey = await fetchBytes('/test/data/authV2/circuit_final.zkey');
    const wasm = await fetchBytes('/test/data/authV2/circuit.wasm');
    const verificationKey = await fetchBytes('/test/data/authV2/verification_key.json');

    const tokenStr = await token.prove(provingKey, wasm);
    expect(await token.verify(verificationKey)).toBeTruthy();

    const parsedToken = await Token.parse(tokenStr);
    expect(await parsedToken.verify(verificationKey)).toBeTruthy();
  });
});
