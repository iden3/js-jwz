import { ProofInputsPreparerHandlerFunc, proving } from '../src/index';
import {
  headerCritical,
  Token,
  headerCircuitId,
  headerAlg,
  headerType,
} from './../src/jwz';

import * as fs from 'fs';
import { fromBigEndian, fromLittleEndian } from '../src/core/util';
import { getCurveFromName } from 'ffjavascript';

afterAll(async () => {
  const curve = await getCurveFromName('bn128');
  curve.terminate();
});

describe('js jws', () => {
  let mock: ProofInputsPreparerHandlerFunc;
  beforeAll(() => {
    mock = (hash: Uint8Array, circuitId: string): Uint8Array => {
      return new TextEncoder().encode(
        `{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"6568187306293073175114267504711682812904598368490904573742495126063294481938","challengeSignatureR8x":"15230565441506590379169832995887068998322005265009046474267743823535028195613","challengeSignatureR8y":"10769958837943955028152112183244447895061604149794975067459918696631541903296","challengeSignatureS":"421650140447062113811542806382702329042840096310563827636625110300562791229","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userID":"379949150130214723420589610911161895495647789006649785264738141299135414272","userRevTreeRoot":"0","userRootsTreeRoot":"0","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313"}`,
      );
    };
  });

  test('jwz new', async () => {
    const payload = 'mymessage';
    const token = new Token(
      proving.provingMethodGroth16AuthInstance,
      payload,
      mock,
    );

    expect(token.alg).toEqual('groth16');
    expect(token.circuitId).toEqual('auth');
    expect(token.raw.header[headerCritical]).toEqual([headerCircuitId]);
    expect(token.raw.header[headerAlg]).toEqual('groth16');
    expect(token.raw.header[headerType]).toEqual('JWZ');
  });

  test('prove method', async () => {
    const payload =
      '{"id":"8507b1f6-6aa8-47cb-aeca-c71f6e69033c","thid":"8507b1f6-6aa8-47cb-aeca-c71f6e69033c","from":"1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/authorization/1.0/request","body":{"reason":"test flow","message":"","callbackUrl":"http://localhost:8080/api/callback?sessionId=1","scope":[]}}';
    const token = new Token(
      proving.provingMethodGroth16AuthInstance,
      payload,
      mock,
    );

    expect(token.alg).toEqual('groth16');
    var encoder = new TextEncoder();
    let provingKey = fs.readFileSync('./test/data/circuit_final.zkey');
    let wasm = fs.readFileSync('./test/data/circuit.wasm');
    let verificationKey = fs.readFileSync('./test/data/verification_key.json');
    let compacted = await token.prove(provingKey, wasm);
    let isValid = await token.verify(verificationKey);
    expect(isValid).toBeTruthy();

    let parsedToken = await Token.parse(
      `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6Ijg1MDdiMWY2LTZhYTgtNDdjYi1hZWNhLWM3MWY2ZTY5MDMzYyIsInRoaWQiOiI4NTA3YjFmNi02YWE4LTQ3Y2ItYWVjYS1jNzFmNmU2OTAzM2MiLCJmcm9tIjoiMTEyNUdKcWd3NllFc0tGd2o2M0dZODdNTXhQTDlrd0RLeFBVaXdNTE5aIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXBsYWluLWpzb24iLCJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3JlcXVlc3QiLCJib2R5Ijp7InJlYXNvbiI6InRlc3QgZmxvdyIsIm1lc3NhZ2UiOiIiLCJjYWxsYmFja1VybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9hcGkvY2FsbGJhY2s_c2Vzc2lvbklkPTEiLCJzY29wZSI6W119fQ.eyJwcm9vZiI6eyJwaV9hIjpbIjIwNTgyODQwNTg5NDMzNDI3NTYwMDEzNjA1MzMxMzMzOTQ1MTUwMDc5ODE0NzgyNTU1OTczNDU1Nzg1NTg4MTc3OTEzODI3MzkwODI2IiwiMTg4NTkyMDY2MzY5MTcyNDI4NjI4NDI4MjU0MjA0OTU5NjUzNDk0MjkxODg4Mjc5NjU2MjE5NDYwMjcyMTYxNzAwMDg4MjI1ODg4MDUiLCIxIl0sInBpX2IiOltbIjgzNjU3Njc2ODEzNTI1MjY2MjUzNDAwOTkxMDI1NDg4NjE4NDQ0OTY0OTczNDA1NTQ3MDc1Mzg4NjAwMDA2ODI2OTY1ODg2Mzk5NjMiLCIyMTQ0NzU5ODU0MDk0NDk3NDAyODMxMjEyMTM3MTAzMzgwMjQ4NTY3Nzk3OTMzODIyNjkxOTk1Njc3NTAzMDEzMjk1MDY0MDc0OTkzMCJdLFsiNDc0NjQ5OTIzODcxNTg4MjExMjQzMTk0MTA3ODIwMTk3NjA5NzE0NTc3MTg5MTY3ODY4MTA5NzI2ODcyOTQxOTkwNTQ2MjAxMDQyNSIsIjIxNzEyMzk5MzQ5OTkyNjY3ODUwNTU4MTQxNjk4MjEwODg3NTQ0Nzg5ODExMjg1ODM0MTkwNjM4OTY3MjU1MDYzMDE1MjU1MjA0MzM5Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxODY0MzI1OTM4OTM0OTAwNDg2MDc0NDM2OTM2NzUzMTIzMzMyNDUzNDYxMDA1NDMwNDQ1MTY2MzA5MjcwMDU3NTAxNDM3MTUyNDI4NCIsIjM1NTU0MDQ0NDUyMTQ1MjY3MTM2MzI3NzQwMzc2Mjk3NTg1Mzg0MTUwMDEwOTUzMjU1Nzk0MTU1MDA2MjMzOTkzMjc2NTc4NDExNzYiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyI2NTY4MTg3MzA2MjkzMDczMTc1MTE0MjY3NTA0NzExNjgyODEyOTA0NTk4MzY4NDkwOTA0NTczNzQyNDk1MTI2MDYzMjk0NDgxOTM4IiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIzNzk5NDkxNTAxMzAyMTQ3MjM0MjA1ODk2MTA5MTExNjE4OTU0OTU2NDc3ODkwMDY2NDk3ODUyNjQ3MzgxNDEyOTkxMzU0MTQyNzIiXX0`,
    );
    isValid = await parsedToken.verify(verificationKey);
    expect(isValid).toBeTruthy();
  });
  test('parse and verify', async () => {
    let verificationKey = fs.readFileSync('./test/data/verification_key.json');

    let parsedToken = await Token.parse(
      `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6Ijg1MDdiMWY2LTZhYTgtNDdjYi1hZWNhLWM3MWY2ZTY5MDMzYyIsInRoaWQiOiI4NTA3YjFmNi02YWE4LTQ3Y2ItYWVjYS1jNzFmNmU2OTAzM2MiLCJmcm9tIjoiMTEyNUdKcWd3NllFc0tGd2o2M0dZODdNTXhQTDlrd0RLeFBVaXdNTE5aIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXBsYWluLWpzb24iLCJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3JlcXVlc3QiLCJib2R5Ijp7InJlYXNvbiI6InRlc3QgZmxvdyIsIm1lc3NhZ2UiOiIiLCJjYWxsYmFja1VybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9hcGkvY2FsbGJhY2s_c2Vzc2lvbklkPTEiLCJzY29wZSI6W119fQ.eyJwcm9vZiI6eyJwaV9hIjpbIjIwNTgyODQwNTg5NDMzNDI3NTYwMDEzNjA1MzMxMzMzOTQ1MTUwMDc5ODE0NzgyNTU1OTczNDU1Nzg1NTg4MTc3OTEzODI3MzkwODI2IiwiMTg4NTkyMDY2MzY5MTcyNDI4NjI4NDI4MjU0MjA0OTU5NjUzNDk0MjkxODg4Mjc5NjU2MjE5NDYwMjcyMTYxNzAwMDg4MjI1ODg4MDUiLCIxIl0sInBpX2IiOltbIjgzNjU3Njc2ODEzNTI1MjY2MjUzNDAwOTkxMDI1NDg4NjE4NDQ0OTY0OTczNDA1NTQ3MDc1Mzg4NjAwMDA2ODI2OTY1ODg2Mzk5NjMiLCIyMTQ0NzU5ODU0MDk0NDk3NDAyODMxMjEyMTM3MTAzMzgwMjQ4NTY3Nzk3OTMzODIyNjkxOTk1Njc3NTAzMDEzMjk1MDY0MDc0OTkzMCJdLFsiNDc0NjQ5OTIzODcxNTg4MjExMjQzMTk0MTA3ODIwMTk3NjA5NzE0NTc3MTg5MTY3ODY4MTA5NzI2ODcyOTQxOTkwNTQ2MjAxMDQyNSIsIjIxNzEyMzk5MzQ5OTkyNjY3ODUwNTU4MTQxNjk4MjEwODg3NTQ0Nzg5ODExMjg1ODM0MTkwNjM4OTY3MjU1MDYzMDE1MjU1MjA0MzM5Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxODY0MzI1OTM4OTM0OTAwNDg2MDc0NDM2OTM2NzUzMTIzMzMyNDUzNDYxMDA1NDMwNDQ1MTY2MzA5MjcwMDU3NTAxNDM3MTUyNDI4NCIsIjM1NTU0MDQ0NDUyMTQ1MjY3MTM2MzI3NzQwMzc2Mjk3NTg1Mzg0MTUwMDEwOTUzMjU1Nzk0MTU1MDA2MjMzOTkzMjc2NTc4NDExNzYiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyI2NTY4MTg3MzA2MjkzMDczMTc1MTE0MjY3NTA0NzExNjgyODEyOTA0NTk4MzY4NDkwOTA0NTczNzQyNDk1MTI2MDYzMjk0NDgxOTM4IiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIzNzk5NDkxNTAxMzAyMTQ3MjM0MjA1ODk2MTA5MTExNjE4OTU0OTU2NDc3ODkwMDY2NDk3ODUyNjQ3MzgxNDEyOTkxMzU0MTQyNzIiXX0`,
    );
    const isValid = await parsedToken.verify(verificationKey);
    expect(isValid).toBeTruthy();
  });
});
