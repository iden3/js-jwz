import { Groth16, AuthV2Circuit } from './../src/common';

import { ProofInputsPreparerHandlerFunc, proving } from '../src/index';
import { Token } from './../src/jwz';
const getCurveFromName = require('ffjavascript').getCurveFromName;
import { base64url as base64 } from 'rfc4648';

import * as fs from 'fs';

afterAll(async () => {
  const curve = await getCurveFromName('bn128');
  curve.terminate();
});

describe('js jws', () => {
  let mock: ProofInputsPreparerHandlerFunc;

  beforeAll(() => {
    mock = (hash: Uint8Array, circuitId: string): Uint8Array => {
      return new TextEncoder().encode(
        `{"genesisID":"19229084873704550357232887142774605442297337229176579229011342091594174977","profileNonce":"0","authClaim":["301485908906857522017021291028488077057","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6110517768249559238193477435454792024732173865488900270849624328650765691494","challengeSignatureR8x":"10923900855019966925146890192107445603460581432515833977084358496785417078889","challengeSignatureR8y":"16158862443157007045624936621448425746188316255879806600364391221203989186031","challengeSignatureS":"51416591880507739389339515804072924841765472826035808894700970942045022090","claimsTreeRoot":"5156125448952672817978035354327403409438120028299513459509442000229340486813","revTreeRoot":"0","rootsTreeRoot":"0","state":"13749793311041076104545663747883540987785640262360452307923674522221753800226","gistRoot":"1243904711429961858774220647610724273798918457991486031567244100767259239747","gistMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"1","gistMtpAuxHv":"1","gistMtpNoAux":"0"}`,
      );
    };
  });

  test('jwz new with payload', async () => {
    const payload = 'mymessage';
    const token = new Token(
      proving.provingMethodGroth16AuthV2Instance,
      payload,
      mock,
    );

    expect(token.alg).toEqual(Groth16);
    expect(token.circuitId).toEqual(AuthV2Circuit);
  });

  test('prove method', async () => {
    const payload = 'mymessage';

    const token = new Token(
      proving.provingMethodGroth16AuthV2Instance,
      payload,
      mock,
    );

    expect(token.alg).toEqual(Groth16);
    const provingKey = fs.readFileSync('./test/data/authV2/circuit_final.zkey');
    const wasm = fs.readFileSync('./test/data/authV2/circuit.wasm');
    const verificationKey = fs.readFileSync(
      './test/data/authV2/verification_key.json',
    );
    const tokenStr = await token.prove(provingKey, wasm);

    const isValid = await token.verify(verificationKey);

    expect(isValid).toBeTruthy();
    const parsedToken = await Token.parse(tokenStr);
    expect(await parsedToken.verify(verificationKey)).toBeTruthy();
  });

  test('parse and verify', async () => {
    const verificationKey = fs.readFileSync(
      './test/data/authV2/verification_key.json',
    );

    const token = await Token.parse(
      `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE5MTU5MDg5MTAwMDkzNDQyMzY0NTY0MjQxOTA3ODQ1MzkxODgxMzM5NDQ3NDkxNTcwNjg2NTk5NDE3MjA0MzUwNTE1ODE0NzYxNDE1IiwiNDQ4MDg2MzgzNDY4MTU2ODM2MTI2NTI1NzgzMzkyMjk1OTE1Mzg5OTQwNDUzMDkxNjcxNTA5NjEyMzg3NTU1MzY0NjM3NjMwNTQzOSIsIjEiXSwicGlfYiI6W1siMTA3MjY0OTYxNTk4OTQwNDAyNTExMDYyMDkyOTA5MjUzOTQ3MDU1MTk0NTYyNTkyMDYwNjgxMTE0MTY4ODQyMDI2MzI0MzY4Nzk1MDAiLCIzODkwMTY0OTc1OTMzOTQzMDY2NTc5ODI3OTk2MDcxNzI0NDg5NjEwNDU1ODQ0NTU5NDQ2MDIwMTk4ODQyNDQwNzk5MzAyNzQyOTk5Il0sWyIxOTY4NjI5MDk3ODAzMzI1MTU1MjczMjAzNTMxMzIyODYwNTE0Mzc3OTUwOTkwNTk1OTAxMTcxODUwNDI1ODQ3NjgxNzY0MzU2NTM1IiwiNDU2OTY3NjE1OTg3MjgwNDYwOTQzMzcyMTcxODAxNjc2MzE2NDczNTQwMzA5Njg4NjE1OTIxMTg0NjA1MDE3MDY1OTk1MTE3NjU4MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTc4ODM0NTM4NjIxNDI2ODI2MjUwNjI3MDA5NTEzMTU0ODQ4OTUyMDA0OTI3MDgwOTk4MzcwNzM1NjAyNzYxNzk4OTM5MzQ5NzQ2MjEiLCI3NzU4ODI2NjAwNTM2MDU3MDUwNTc2MDMxMDE4NjQ0MDk4NjQyODMxMTE5MzQ2ODM3NjgyMTMzNDU5MjgyMjg4NzExMjgyMzA2NjM4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMTkyMjkwODQ4NzM3MDQ1NTAzNTcyMzI4ODcxNDI3NzQ2MDU0NDIyOTczMzcyMjkxNzY1NzkyMjkwMTEzNDIwOTE1OTQxNzQ5NzciLCI2MTEwNTE3NzY4MjQ5NTU5MjM4MTkzNDc3NDM1NDU0NzkyMDI0NzMyMTczODY1NDg4OTAwMjcwODQ5NjI0MzI4NjUwNzY1NjkxNDk0IiwiMTI0MzkwNDcxMTQyOTk2MTg1ODc3NDIyMDY0NzYxMDcyNDI3Mzc5ODkxODQ1Nzk5MTQ4NjAzMTU2NzI0NDEwMDc2NzI1OTIzOTc0NyJdfQ`,
    );
    const isValid = await token.verify(verificationKey);
    expect(isValid).toBeTruthy();

    const proofByte = base64.parse(
      'eyJwcm9vZiI6eyJwaV9hIjpbIjE5MTU5MDg5MTAwMDkzNDQyMzY0NTY0MjQxOTA3ODQ1MzkxODgxMzM5NDQ3NDkxNTcwNjg2NTk5NDE3MjA0MzUwNTE1ODE0NzYxNDE1IiwiNDQ4MDg2MzgzNDY4MTU2ODM2MTI2NTI1NzgzMzkyMjk1OTE1Mzg5OTQwNDUzMDkxNjcxNTA5NjEyMzg3NTU1MzY0NjM3NjMwNTQzOSIsIjEiXSwicGlfYiI6W1siMTA3MjY0OTYxNTk4OTQwNDAyNTExMDYyMDkyOTA5MjUzOTQ3MDU1MTk0NTYyNTkyMDYwNjgxMTE0MTY4ODQyMDI2MzI0MzY4Nzk1MDAiLCIzODkwMTY0OTc1OTMzOTQzMDY2NTc5ODI3OTk2MDcxNzI0NDg5NjEwNDU1ODQ0NTU5NDQ2MDIwMTk4ODQyNDQwNzk5MzAyNzQyOTk5Il0sWyIxOTY4NjI5MDk3ODAzMzI1MTU1MjczMjAzNTMxMzIyODYwNTE0Mzc3OTUwOTkwNTk1OTAxMTcxODUwNDI1ODQ3NjgxNzY0MzU2NTM1IiwiNDU2OTY3NjE1OTg3MjgwNDYwOTQzMzcyMTcxODAxNjc2MzE2NDczNTQwMzA5Njg4NjE1OTIxMTg0NjA1MDE3MDY1OTk1MTE3NjU4MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTc4ODM0NTM4NjIxNDI2ODI2MjUwNjI3MDA5NTEzMTU0ODQ4OTUyMDA0OTI3MDgwOTk4MzcwNzM1NjAyNzYxNzk4OTM5MzQ5NzQ2MjEiLCI3NzU4ODI2NjAwNTM2MDU3MDUwNTc2MDMxMDE4NjQ0MDk4NjQyODMxMTE5MzQ2ODM3NjgyMTMzNDU5MjgyMjg4NzExMjgyMzA2NjM4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMTkyMjkwODQ4NzM3MDQ1NTAzNTcyMzI4ODcxNDI3NzQ2MDU0NDIyOTczMzcyMjkxNzY1NzkyMjkwMTEzNDIwOTE1OTQxNzQ5NzciLCI2MTEwNTE3NzY4MjQ5NTU5MjM4MTkzNDc3NDM1NDU0NzkyMDI0NzMyMTczODY1NDg4OTAwMjcwODQ5NjI0MzI4NjUwNzY1NjkxNDk0IiwiMTI0MzkwNDcxMTQyOTk2MTg1ODc3NDIyMDY0NzYxMDcyNDI3Mzc5ODkxODQ1Nzk5MTQ4NjAzMTU2NzI0NDEwMDc2NzI1OTIzOTc0NyJdfQ',
      { loose: true },
    );
    const zkProof = JSON.parse(new TextDecoder().decode(proofByte));

    expect(zkProof.pub_signals).toEqual(token.zkProof.pub_signals);
    expect(zkProof.proof).toEqual(token.zkProof.proof);
    expect(AuthV2Circuit).toEqual(token.circuitId);
    expect(Groth16).toEqual(token.alg);
  });
});
