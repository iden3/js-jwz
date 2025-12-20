import { Groth16, AuthV2Circuit, AuthV3Circuit, AuthV3_8_32Circuit } from './../src/common';

import { ProofInputsPreparerHandlerFunc, proving } from '../src/index';
import { Token } from './../src/jwz';
import { base64url as base64 } from 'rfc4648';
import { test, describe, beforeAll, expect } from 'vitest';
import * as fs from 'fs';

describe('authV2Groth16', () => {
  let mock: ProofInputsPreparerHandlerFunc;

  beforeAll(() => {
    mock = (): Promise<Uint8Array> => {
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

describe('authV3Groth16', () => {
  let mock: ProofInputsPreparerHandlerFunc;

  beforeAll(() => {
    mock = (): Promise<Uint8Array> => {
      return Promise.resolve(
        new TextEncoder().encode(
          `{"genesisID":"23273167900576580892722615617815475823351560716009055944677723144398443009","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["20643387758736831799596675626240785455902781070167728593409367019626753600795","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"15997052917246064036592446616808680316677720366381306147286202311286142126826","challengeSignatureR8x":"14814416808449860798229850027466815499618347907194745718733221355391260028283","challengeSignatureR8y":"4112444211451581299965320230239613118199750678931648705294867682050395522623","challengeSignatureS":"2201595010244638725232493661689550828769979367760557441084895625977276980737","claimsTreeRoot":"8794724428328826645726823821449086761079599815895679828313419678997386356573","revTreeRoot":"0","rootsTreeRoot":"0","state":"7115004997868594253010848596868364067574661249707337517331323113105592633327","gistRoot":"20746967949242970504735775681024928984312199406892280437050499102607067526238","gistMtp":["0","0","0","1243904711429961858774220647610724273798918457991486031567244100767259239747","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"0","gistMtpAuxHv":"0","gistMtpNoAux":"0"}`
        )
      );
    };
  });

  test('jwz new with payload', async () => {
    const payload = 'mymessage';
    const token = new Token(proving.provingMethodGroth16AuthV3Instance, payload, mock);

    expect(token.alg).toEqual(Groth16);
    expect(token.circuitId).toEqual(AuthV3Circuit);
  });

  test('prove method', async () => {
    const payload = 'mymessage';

    const token = new Token(proving.provingMethodGroth16AuthV3Instance, payload, mock);

    expect(token.alg).toEqual(Groth16);
    const provingKey = fs.readFileSync('./test/data/authV3/circuit_final.zkey');
    const wasm = fs.readFileSync('./test/data/authV3/circuit.wasm');
    const verificationKey = fs.readFileSync('./test/data/authV3/verification_key.json');
    const tokenStr = await token.prove(provingKey, wasm);

    const isValid = await token.verify(verificationKey);

    expect(isValid).toBeTruthy();
    const parsedToken = await Token.parse(tokenStr);
    expect(await parsedToken.verify(verificationKey)).toBeTruthy();
  });

  test('parse and verify', async () => {
    const verificationKey = fs.readFileSync('./test/data/authV3/verification_key.json');

    const token = await Token.parse(
      `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE1NTkyNjM2NDQ2MTcwNzcyNDc3NDEyMjI0OTIzNTM2OTg1MDA5OTc4MDE2MTg4MjMyOTkzODA5ODA3MzUzNjU4MjgxNjIxMDYwNDg5IiwiMTI5MzU1MjA3NzczNDc1Mjk5NTQyNDY2NDQ0MTgwNTM2OTYxMTc4OTMwNTUzMDMyNzgzNjMyNTQxNzk3NzU2ODE5OTkyNzQ1NDYxMzUiLCIxIl0sInBpX2IiOltbIjE5Mjc2ODU1ODY2MTQ3NjA4MDE5MDIwMDI5NTEwMzg3NDMwODQxNjcxMzM0NDM4ODM0MTg0NTEwMTkyNTI0MjAxNDU5MjEyNTEyMTEiLCIxODAwODM4NjQ5MDMyNDcxNTA1OTMxNjQ0MjExNjk3MDcyNDIxMDY2MjU5ODIwNDkxMzczNzc5Mjk4MDkzMTA5NTY4ODEzNzk3NjAxOCJdLFsiNDY1MjQyMTA1NjIwNzEyMTQ3MDc1MjQ5MDEyMTgyMzQxMjMwNzM3MjMwMDE5MTY3NzQwNjI1MjQxMjMxMDc0ODM3NTkzNTUxMTUzMCIsIjQ4OTg4MDM2NDU0OTYyNzExOTA2MTIxMTA5MDAzMjE2MDE2NjQwMTYxMjUzMjk3NTI5NjMyNDQ4NDY5OTYzNzU0Njk0MTAwNzA3NjUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjc4ODM3OTQ3OTE3NDUyNTkzNTM0OTc4NzgyMzQ3NDk2MjE4NzYwNTcwODQ3MDE1MDAwMDQyNTMwNTQxMDMwNDkzNjcxNjczMDQ5MTgiLCI2ODU3MTgwNDQwNDMwNDk1NDc4MzkwNTA5NDQ5NzUzNjYxODM2NzkyMDAwMTc4MTU3OTA2NTM1MzUzNDkxMDYwMzM2MTE4NDg4ODgiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjMyNzMxNjc5MDA1NzY1ODA4OTI3MjI2MTU2MTc4MTU0NzU4MjMzNTE1NjA3MTYwMDkwNTU5NDQ2Nzc3MjMxNDQzOTg0NDMwMDkiLCIxNTk5NzA1MjkxNzI0NjA2NDAzNjU5MjQ0NjYxNjgwODY4MDMxNjY3NzcyMDM2NjM4MTMwNjE0NzI4NjIwMjMxMTI4NjE0MjEyNjgyNiIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19`
    );

    const isValid = await token.verify(verificationKey);
    expect(isValid).toBeTruthy();

    const proofByte = base64.parse(
      'eyJwcm9vZiI6eyJwaV9hIjpbIjE1NTkyNjM2NDQ2MTcwNzcyNDc3NDEyMjI0OTIzNTM2OTg1MDA5OTc4MDE2MTg4MjMyOTkzODA5ODA3MzUzNjU4MjgxNjIxMDYwNDg5IiwiMTI5MzU1MjA3NzczNDc1Mjk5NTQyNDY2NDQ0MTgwNTM2OTYxMTc4OTMwNTUzMDMyNzgzNjMyNTQxNzk3NzU2ODE5OTkyNzQ1NDYxMzUiLCIxIl0sInBpX2IiOltbIjE5Mjc2ODU1ODY2MTQ3NjA4MDE5MDIwMDI5NTEwMzg3NDMwODQxNjcxMzM0NDM4ODM0MTg0NTEwMTkyNTI0MjAxNDU5MjEyNTEyMTEiLCIxODAwODM4NjQ5MDMyNDcxNTA1OTMxNjQ0MjExNjk3MDcyNDIxMDY2MjU5ODIwNDkxMzczNzc5Mjk4MDkzMTA5NTY4ODEzNzk3NjAxOCJdLFsiNDY1MjQyMTA1NjIwNzEyMTQ3MDc1MjQ5MDEyMTgyMzQxMjMwNzM3MjMwMDE5MTY3NzQwNjI1MjQxMjMxMDc0ODM3NTkzNTUxMTUzMCIsIjQ4OTg4MDM2NDU0OTYyNzExOTA2MTIxMTA5MDAzMjE2MDE2NjQwMTYxMjUzMjk3NTI5NjMyNDQ4NDY5OTYzNzU0Njk0MTAwNzA3NjUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjc4ODM3OTQ3OTE3NDUyNTkzNTM0OTc4NzgyMzQ3NDk2MjE4NzYwNTcwODQ3MDE1MDAwMDQyNTMwNTQxMDMwNDkzNjcxNjczMDQ5MTgiLCI2ODU3MTgwNDQwNDMwNDk1NDc4MzkwNTA5NDQ5NzUzNjYxODM2NzkyMDAwMTc4MTU3OTA2NTM1MzUzNDkxMDYwMzM2MTE4NDg4ODgiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjMyNzMxNjc5MDA1NzY1ODA4OTI3MjI2MTU2MTc4MTU0NzU4MjMzNTE1NjA3MTYwMDkwNTU5NDQ2Nzc3MjMxNDQzOTg0NDMwMDkiLCIxNTk5NzA1MjkxNzI0NjA2NDAzNjU5MjQ0NjYxNjgwODY4MDMxNjY3NzcyMDM2NjM4MTMwNjE0NzI4NjIwMjMxMTI4NjE0MjEyNjgyNiIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19',
      { loose: true }
    );
    const zkProof = JSON.parse(new TextDecoder().decode(proofByte));

    expect(zkProof.pub_signals).toEqual(token.zkProof.pub_signals);
    expect(zkProof.proof).toEqual(token.zkProof.proof);
    expect(AuthV3Circuit).toEqual(token.circuitId);
    expect(Groth16).toEqual(token.alg);
  });
});

describe('authV3_8_32-Groth16', () => {
  let mock: ProofInputsPreparerHandlerFunc;

  beforeAll(() => {
    mock = (): Promise<Uint8Array> => {
      return Promise.resolve(
        new TextEncoder().encode(
          `{"genesisID":"23273167900576580892722615617815475823351560716009055944677723144398443009","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["20643387758736831799596675626240785455902781070167728593409367019626753600795","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6807542932739626352372202747650479413343284843713199903849051801035429042865","challengeSignatureR8x":"7525126381917356257636372917552188361117494179201353025019127810758731021916","challengeSignatureR8y":"20415806316264090304714063012907270619258996127071363004039215148633807127483","challengeSignatureS":"251992476641732412701642926724758498615919121424404336076731271483813524620","claimsTreeRoot":"8794724428328826645726823821449086761079599815895679828313419678997386356573","revTreeRoot":"0","rootsTreeRoot":"0","state":"7115004997868594253010848596868364067574661249707337517331323113105592633327","gistRoot":"20746967949242970504735775681024928984312199406892280437050499102607067526238","gistMtp":["0","0","0","1243904711429961858774220647610724273798918457991486031567244100767259239747","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"0","gistMtpAuxHv":"0","gistMtpNoAux":"0"}`
        )
      );
    };
  });

  test('jwz new with payload', async () => {
    const payload = 'mymessage';
    const token = new Token(proving.provingMethodGroth16AuthV3_8_32Instance, payload, mock);

    expect(token.alg).toEqual(Groth16);
    expect(token.circuitId).toEqual(AuthV3_8_32Circuit);
  });

  test('prove method', async () => {
    const payload = 'mymessage';

    const token = new Token(proving.provingMethodGroth16AuthV3_8_32Instance, payload, mock);

    expect(token.alg).toEqual(Groth16);
    const provingKey = fs.readFileSync('./test/data/authV3-8-32/circuit_final.zkey');
    const wasm = fs.readFileSync('./test/data/authV3-8-32/circuit.wasm');
    const verificationKey = fs.readFileSync('./test/data/authV3-8-32/verification_key.json');
    const tokenStr = await token.prove(provingKey, wasm);
    const isValid = await token.verify(verificationKey);

    expect(isValid).toBeTruthy();
    const parsedToken = await Token.parse(tokenStr);
    expect(await parsedToken.verify(verificationKey)).toBeTruthy();
  });

  test('parse and verify', async () => {
    const verificationKey = fs.readFileSync('./test/data/authV3-8-32/verification_key.json');

    const token = await Token.parse(
      `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzLTgtMzIiLCJjcml0IjpbImNpcmN1aXRJZCJdLCJ0eXAiOiJKV1oifQ.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjIwNDg3MDI1OTkyOTcyOTYyODc3OTY3MjQzODk1MzE1ODE3MTM3MjMzNDMzMjU4NDU2MjQ0NTE2NzQwNjEzODU2NzE4MjcwNzQwMzciLCIxOTEwNDA4NTI2MTk0MzQ0NjMxMjI0NzQzMjc4OTkxNDE1OTg3MjYwNjA0OTU5Mjk0NTc0NzU1NDgzOTU0NzA5Nzc3NDIzNDY2ODU2OCIsIjEiXSwicGlfYiI6W1siNjE2MjUzNTAxMDg3NjE5MzQzNDUwOTExNTYxOTA2MDEwMTY4OTIwNDY1NTEwNzIxNDEwMzU5OTIyNzUyNzY2ODQwMDQ5MTM3MzQxMSIsIjkyNzIxMDQ1NDM0NTE0MDM1MTc4NTAxODIxMzUwMjQ3OTM5MjY3NDc4MDMwMTg2NzgyOTA3NjA3MjEzNzYzNzQ5ODE2ODM5OTY3NDEiXSxbIjIwMjYwNDAxMTQ2NTYwMzY3MTEzOTMwODcyMjUwMjMwMjA1ODYyNDkxMzA0NDgwNzczODY1ODY5OTAzNTY3MjEzMjkwODU5MDU5NDY4IiwiOTY4MDc2NTA1MzA3NDk4NDAzNTk3NzU1NDY5MTQ2MzAwNTIwOTE0Njg0MjcwMjA5ODIxOTA1MDYyMDExNjE5NDU3OTc2MzM0NDcwNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNzYyNzc1NDM4MzY4ODY3MDkwOTcyNzY5MzIwNjYzNzA2MjIzNjM2NzYyMDIzODQ5MTkwMDM0ODQ5MzAzNjQzODczOTMyOTgzMzM4IiwiODI2MzczODE2MjkyMzU0NTM4MzA1MTQ1MzA0MTkzNTI5MDgxMzI0NzM3MzA0NTE3NjgwNjY5Nzc5NzIwMzg3OTYzNjgwMzY2MTc0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMjczMTY3OTAwNTc2NTgwODkyNzIyNjE1NjE3ODE1NDc1ODIzMzUxNTYwNzE2MDA5MDU1OTQ0Njc3NzIzMTQ0Mzk4NDQzMDA5IiwiNjgwNzU0MjkzMjczOTYyNjM1MjM3MjIwMjc0NzY1MDQ3OTQxMzM0MzI4NDg0MzcxMzE5OTkwMzg0OTA1MTgwMTAzNTQyOTA0Mjg2NSIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19`
    );

    const isValid = await token.verify(verificationKey);
    expect(isValid).toBeTruthy();

    const proofByte = base64.parse(
      'eyJwcm9vZiI6eyJwaV9hIjpbIjIwNDg3MDI1OTkyOTcyOTYyODc3OTY3MjQzODk1MzE1ODE3MTM3MjMzNDMzMjU4NDU2MjQ0NTE2NzQwNjEzODU2NzE4MjcwNzQwMzciLCIxOTEwNDA4NTI2MTk0MzQ0NjMxMjI0NzQzMjc4OTkxNDE1OTg3MjYwNjA0OTU5Mjk0NTc0NzU1NDgzOTU0NzA5Nzc3NDIzNDY2ODU2OCIsIjEiXSwicGlfYiI6W1siNjE2MjUzNTAxMDg3NjE5MzQzNDUwOTExNTYxOTA2MDEwMTY4OTIwNDY1NTEwNzIxNDEwMzU5OTIyNzUyNzY2ODQwMDQ5MTM3MzQxMSIsIjkyNzIxMDQ1NDM0NTE0MDM1MTc4NTAxODIxMzUwMjQ3OTM5MjY3NDc4MDMwMTg2NzgyOTA3NjA3MjEzNzYzNzQ5ODE2ODM5OTY3NDEiXSxbIjIwMjYwNDAxMTQ2NTYwMzY3MTEzOTMwODcyMjUwMjMwMjA1ODYyNDkxMzA0NDgwNzczODY1ODY5OTAzNTY3MjEzMjkwODU5MDU5NDY4IiwiOTY4MDc2NTA1MzA3NDk4NDAzNTk3NzU1NDY5MTQ2MzAwNTIwOTE0Njg0MjcwMjA5ODIxOTA1MDYyMDExNjE5NDU3OTc2MzM0NDcwNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNzYyNzc1NDM4MzY4ODY3MDkwOTcyNzY5MzIwNjYzNzA2MjIzNjM2NzYyMDIzODQ5MTkwMDM0ODQ5MzAzNjQzODczOTMyOTgzMzM4IiwiODI2MzczODE2MjkyMzU0NTM4MzA1MTQ1MzA0MTkzNTI5MDgxMzI0NzM3MzA0NTE3NjgwNjY5Nzc5NzIwMzg3OTYzNjgwMzY2MTc0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMjczMTY3OTAwNTc2NTgwODkyNzIyNjE1NjE3ODE1NDc1ODIzMzUxNTYwNzE2MDA5MDU1OTQ0Njc3NzIzMTQ0Mzk4NDQzMDA5IiwiNjgwNzU0MjkzMjczOTYyNjM1MjM3MjIwMjc0NzY1MDQ3OTQxMzM0MzI4NDg0MzcxMzE5OTkwMzg0OTA1MTgwMTAzNTQyOTA0Mjg2NSIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19',
      { loose: true }
    );
    const zkProof = JSON.parse(new TextDecoder().decode(proofByte));

    expect(zkProof.pub_signals).toEqual(token.zkProof.pub_signals);
    expect(zkProof.proof).toEqual(token.zkProof.proof);
    expect(AuthV3_8_32Circuit).toEqual(token.circuitId);
    expect(Groth16).toEqual(token.alg);
  });
});