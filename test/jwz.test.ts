import { ProofInputsPreparerHandlerFunc } from '../src/proving';
import { provingMethodGroth16AuthInstance } from './../src/authGroth16';
import {
  headerCritical,
  Token,
  headerCircuitId,
  headerAlg,
  headerType,
} from './../src/jwz';

import * as fs from "fs" 
import { fromBigEndian, fromLittleEndian } from '../src/core/util';
import { getCurveFromName } from 'ffjavascript';

afterAll(async () => {
  const curve = await getCurveFromName('bn128');
  curve.terminate();
});

describe('js jws', () => {
  let mock: ProofInputsPreparerHandlerFunc;
  beforeAll(() => {
    mock = (hash: Uint8Array, circuitId: string): Uint8Array =>{
      return new TextEncoder().encode(
        `{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"19054333970885023780123560936675456700861469068603321884718748961750930466794","challengeSignatureR8x":"4219150445599866015975338408000561684366422973912091598548631071677167824366","challengeSignatureR8y":"12598735963096034383552425395289278326931986118036778264141841465661466935045","challengeSignatureS":"482456738038705898703405023807226003538372788878082557708969187456494192709","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userID":"379949150130214723420589610911161895495647789006649785264738141299135414272","userRevTreeRoot":"0","userRootsTreeRoot":"0","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313"}`,
      );
    }

     
  });

  test('hash', async () => {
    const payload = 'mymessage';
    const token = new Token(provingMethodGroth16AuthInstance, payload, mock);

    expect(token.alg).toEqual('groth16');
    expect(token.circuitId).toEqual('auth');
    expect(token.raw.header[headerCritical]).toEqual([headerCircuitId]);
    expect(token.raw.header[headerAlg]).toEqual('groth16');
    expect(token.raw.header[headerType]).toEqual('JWZ');
  });

  test('prove method', async () => {
    const payload = 'mymessage';
    const token = new Token(provingMethodGroth16AuthInstance, payload, mock);

    expect(token.alg).toEqual('groth16');
    var encoder = new TextEncoder();
    let provingKey = fs.readFileSync('./test/data/circuit_final.zkey');
    let wasm = fs.readFileSync('./test/data/circuit.wasm');
    let verificationKey = fs.readFileSync('./test/data/verification_key.json');
    let copmacted = await token.prove(provingKey,wasm)
    let isValid = await token.verify(verificationKey)
    expect(isValid).toBeTruthy()

    let parsedToken = await Token.parse(copmacted)
    isValid = await parsedToken.verify(verificationKey)
    expect(isValid).toBeTruthy()

  });
});
