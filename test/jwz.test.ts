import { Groth16, AuthV2Circuit } from './../src/common';

import { ProofInputsPreparerHandlerFunc, proving } from '../src/index';
import { Token } from './../src/jwz';
import { base64url as base64 } from 'rfc4648';

import * as fs from 'fs';

describe('authV2Groth16', () => {
  let mock: ProofInputsPreparerHandlerFunc;

  beforeAll(() => {
    mock = (hash: Uint8Array, circuitId: string): Promise<Uint8Array> => {
      return Promise.resolve(
        new TextEncoder().encode(
          `{"genesisID":"23148936466334350744548790012294489365207440754509988986684797708370051073","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6110517768249559238193477435454792024732173865488900270849624328650765691494","challengeSignatureR8x":"10923900855019966925146890192107445603460581432515833977084358496785417078889","challengeSignatureR8y":"16158862443157007045624936621448425746188316255879806600364391221203989186031","challengeSignatureS":"51416591880507739389339515804072924841765472826035808894700970942045022090","claimsTreeRoot":"8162166103065016664685834856644195001371303013149727027131225893397958846382","revTreeRoot":"0","rootsTreeRoot":"0","state":"8039964009611210398788855768060749920589777058607598891238307089541758339342","gistRoot":"1243904711429961858774220647610724273798918457991486031567244100767259239747","gistMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"1","gistMtpAuxHv":"1","gistMtpNoAux":"0"}`
        )
      );
    };
  });

  test('jwz new with payload', async () => {
    const payload = 'mymessage';
    const token = new Token(proving.provingMethodGroth16AuthV2Instance, payload, mock);

    expect(token.alg).toEqual(Groth16);
    expect(token.circuitId).toEqual(AuthV2Circuit);
  });

  test('prove method', async () => {
    const payload = 'mymessage';

    const token = new Token(proving.provingMethodGroth16AuthV2Instance, payload, mock);

    expect(token.alg).toEqual(Groth16);
    const provingKey = fs.readFileSync('./test/data/authV2/circuit_final.zkey');
    const wasm = fs.readFileSync('./test/data/authV2/circuit.wasm');
    const verificationKey = fs.readFileSync('./test/data/authV2/verification_key.json');
    const tokenStr = await token.prove(provingKey, wasm);

    const isValid = await token.verify(verificationKey);

    expect(isValid).toBeTruthy();
    const parsedToken = await Token.parse(tokenStr);
    expect(await parsedToken.verify(verificationKey)).toBeTruthy();
  });

  test('parse and verify', async () => {
    const verificationKey = fs.readFileSync('./test/data/authV2/verification_key.json');

    const token = await Token.parse(
      `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjU4OTA4MTc2NDc0NDY4MzQ2MDU3NjU3NzA0NTExMDIyMDg4NjMyMDkxNDgwMTE5NDgzNjA0MDQ3NDU0ODA2NzE1NDM2MjU5MTkwNDIiLCI2OTY1MzI0OTI3MDYzMDQxOTU2NTIwODg5ODU1MDcxNjU1OTg5Mzg4NzQyODM1ODgzOTI1NjU4MDI1NDE0MjM4OTQ2OTkxNjE1ODMwIiwiMSJdLCJwaV9iIjpbWyIxNjgwMjkyNTc5OTM3NjI4MDExOTc1MTk2MTk1MDEzNjQ5NjkyMjMyOTU1NDI5Mjc0Nzc5OTE1NDI2MDQwMzMwNTM0Njc1NDU1Mzk5NCIsIjIwNzkzNDcyNDAwMzczNDkzMjIyNzAyNDY4NDcxMjQzNzcwMzk3NzY1MzY0OTc3NDA0NDQwNTQ2Mzc0MTkxNjU2OTM0NDE3Mjg1MDQxIl0sWyI2MTI1MjcxNjYyOTI4NDUzMjQ5NDgyMjc5MjQ2ODA2NTIxNTE2MzU5NDQwMTcxMDM1MzgxMzU4OTI3MjI4Njc2NTQxNTc0NTg5MDkxIiwiNTY4MDc3OTcxNTc0MjMyMjI0ODQyOTM0NDc1ODA5NDk0MzMyMzE1OTIzOTQzNjkyNzI3MjM3NDEwOTkxMzYzOTAyMjM2NDMyMjYwNiJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTQ4MTkzNTE5MTMwNTA0OTM5MTA3MjkxMDkxNzE2ODQzNzA0OTI4MjQyMzc3NDQ5MDM4NzMwNDU3NzM3MTI4Mjc0Mjc1NTc3ODYwOCIsIjEyMDMxNDE1NjE1ODExNTEzNzc2OTcwMDYwOTgzMDk2NTMxNzcwMTcwNDAxMjkzODEwMTQwMDY2ODM1NzkyMjk4NTcwNDQxMzcyMTg3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMTQ4OTM2NDY2MzM0MzUwNzQ0NTQ4NzkwMDEyMjk0NDg5MzY1MjA3NDQwNzU0NTA5OTg4OTg2Njg0Nzk3NzA4MzcwMDUxMDczIiwiNjExMDUxNzc2ODI0OTU1OTIzODE5MzQ3NzQzNTQ1NDc5MjAyNDczMjE3Mzg2NTQ4ODkwMDI3MDg0OTYyNDMyODY1MDc2NTY5MTQ5NCIsIjEyNDM5MDQ3MTE0Mjk5NjE4NTg3NzQyMjA2NDc2MTA3MjQyNzM3OTg5MTg0NTc5OTE0ODYwMzE1NjcyNDQxMDA3NjcyNTkyMzk3NDciXX0`
    );
    const isValid = await token.verify(verificationKey);
    expect(isValid).toBeTruthy();

    const proofByte = base64.parse(
      'eyJwcm9vZiI6eyJwaV9hIjpbIjU4OTA4MTc2NDc0NDY4MzQ2MDU3NjU3NzA0NTExMDIyMDg4NjMyMDkxNDgwMTE5NDgzNjA0MDQ3NDU0ODA2NzE1NDM2MjU5MTkwNDIiLCI2OTY1MzI0OTI3MDYzMDQxOTU2NTIwODg5ODU1MDcxNjU1OTg5Mzg4NzQyODM1ODgzOTI1NjU4MDI1NDE0MjM4OTQ2OTkxNjE1ODMwIiwiMSJdLCJwaV9iIjpbWyIxNjgwMjkyNTc5OTM3NjI4MDExOTc1MTk2MTk1MDEzNjQ5NjkyMjMyOTU1NDI5Mjc0Nzc5OTE1NDI2MDQwMzMwNTM0Njc1NDU1Mzk5NCIsIjIwNzkzNDcyNDAwMzczNDkzMjIyNzAyNDY4NDcxMjQzNzcwMzk3NzY1MzY0OTc3NDA0NDQwNTQ2Mzc0MTkxNjU2OTM0NDE3Mjg1MDQxIl0sWyI2MTI1MjcxNjYyOTI4NDUzMjQ5NDgyMjc5MjQ2ODA2NTIxNTE2MzU5NDQwMTcxMDM1MzgxMzU4OTI3MjI4Njc2NTQxNTc0NTg5MDkxIiwiNTY4MDc3OTcxNTc0MjMyMjI0ODQyOTM0NDc1ODA5NDk0MzMyMzE1OTIzOTQzNjkyNzI3MjM3NDEwOTkxMzYzOTAyMjM2NDMyMjYwNiJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTQ4MTkzNTE5MTMwNTA0OTM5MTA3MjkxMDkxNzE2ODQzNzA0OTI4MjQyMzc3NDQ5MDM4NzMwNDU3NzM3MTI4Mjc0Mjc1NTc3ODYwOCIsIjEyMDMxNDE1NjE1ODExNTEzNzc2OTcwMDYwOTgzMDk2NTMxNzcwMTcwNDAxMjkzODEwMTQwMDY2ODM1NzkyMjk4NTcwNDQxMzcyMTg3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMTQ4OTM2NDY2MzM0MzUwNzQ0NTQ4NzkwMDEyMjk0NDg5MzY1MjA3NDQwNzU0NTA5OTg4OTg2Njg0Nzk3NzA4MzcwMDUxMDczIiwiNjExMDUxNzc2ODI0OTU1OTIzODE5MzQ3NzQzNTQ1NDc5MjAyNDczMjE3Mzg2NTQ4ODkwMDI3MDg0OTYyNDMyODY1MDc2NTY5MTQ5NCIsIjEyNDM5MDQ3MTE0Mjk5NjE4NTg3NzQyMjA2NDc2MTA3MjQyNzM3OTg5MTg0NTc5OTE0ODYwMzE1NjcyNDQxMDA3NjcyNTkyMzk3NDciXX0',
      { loose: true }
    );
    const zkProof = JSON.parse(new TextDecoder().decode(proofByte));

    expect(zkProof.pub_signals).toEqual(token.zkProof.pub_signals);
    expect(zkProof.proof).toEqual(token.zkProof.proof);
    expect(AuthV2Circuit).toEqual(token.circuitId);
    expect(Groth16).toEqual(token.alg);
  });
});
