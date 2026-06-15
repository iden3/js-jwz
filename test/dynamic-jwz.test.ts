import * as fs from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { type DynamicProofInputsPreparerHandlerFunc, proving, Token } from '../src';
import { AuthV3Circuit } from './../src/common';

describe('dynamicProve and dynamicVerify', () => {
  // Mock inputs for authV3 circuit
  const authV3_8_32_Input = `{"genesisID":"23273167900576580892722615617815475823351560716009055944677723144398443009","profileNonce":"10","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"15997052917246064036592446616808680316677720366381306147286202311286142126826","challengeSignatureR8x":"14814416808449860798229850027466815499618347907194745718733221355391260028283","challengeSignatureR8y":"4112444211451581299965320230239613118199750678931648705294867682050395522623","challengeSignatureS":"2201595010244638725232493661689550828769979367760557441084895625977276980737","claimsTreeRoot":"8162166103065016664685834856644195001371303013149727027131225893397958846382","revTreeRoot":"0","rootsTreeRoot":"0","state":"8039964009611210398788855768060749920589777058607598891238307089541758339342","gistRoot":"1243904711429961858774220647610724273798918457991486031567244100767259239747","gistMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"1","gistMtpAuxHv":"1","gistMtpNoAux":"0"}`;

  it('should prove and verify with authV3 and authV3-8-32 circuits using dynamic inputs preparer', async () => {
    const payload = 'mymessage';

    // Create a DynamicProofInputsPreparerHandlerFunc that returns authV3 inputs
    const dynamicInputsPreparer: DynamicProofInputsPreparerHandlerFunc = (): Promise<{
      inputs: Uint8Array;
      targetCircuitId: string;
    }> => {
      return Promise.resolve({
        inputs: new TextEncoder().encode(authV3_8_32_Input),
        targetCircuitId: `${AuthV3Circuit}-8-32`
      });
    };

    const token = new Token(proving.provingMethodGroth16AuthV3Instance, payload);

    const loadKeys = async (
      circuitId: string
    ): Promise<{ provingKey: Uint8Array; wasm: Uint8Array; verificationKey: Uint8Array }> => {
      const circuitPath = path.join(__dirname, 'data', circuitId);

      const [provingKey, wasm, verificationKey] = await Promise.all([
        fs.readFile(path.join(circuitPath, 'circuit_final.zkey')),
        fs.readFile(path.join(circuitPath, 'circuit.wasm')),
        fs.readFile(path.join(circuitPath, 'verification_key.json'))
      ]);

      return { provingKey, wasm, verificationKey };
    };

    const authV3_8_32_keys = await loadKeys(`${AuthV3Circuit}-8-32`);
    const authV3_keys = await loadKeys(AuthV3Circuit);

    const _tokenStr = await token.dynamicProve({
      provingParams: [
        {
          circuitId: `${AuthV3Circuit}-8-32`,
          provingKey: authV3_8_32_keys.provingKey,
          wasm: authV3_8_32_keys.wasm
        },
        { circuitId: AuthV3Circuit, provingKey: authV3_keys.provingKey, wasm: authV3_keys.wasm }
      ],
      inputsPreparerFn: dynamicInputsPreparer
    });

    // The proof protocol should contain the target circuit ID
    expect(token.zkProof.proof.protocol).toContain(`${AuthV3Circuit}-8-32`);

    // Verify using dynamicVerify with verification keys map
    const isValid = await token.dynamicVerify({
      verificationKeysMap: [
        {
          circuitId: `${AuthV3Circuit}-8-32`,
          verificationKey: authV3_8_32_keys.verificationKey
        },
        { circuitId: AuthV3Circuit, verificationKey: authV3_keys.verificationKey }
      ]
    });

    expect(isValid).toBeTruthy();
  });
});
