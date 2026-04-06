import { test, expect, describe } from 'vitest';
import type { Token as TokenType, ZKProof } from '../src/index';

// The IIFE exposes everything under window.JWZ (injected by iife-setup.ts)
declare const JWZ: typeof import('../src/index');

const VERIFICATION_KEY_URL = '/test/data/authV2/verification_key.json';

const JWZ_TOKEN =
  'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjU4OTA4MTc2NDc0NDY4MzQ2MDU3NjU3NzA0NTExMDIyMDg4NjMyMDkxNDgwMTE5NDgzNjA0MDQ3NDU0ODA2NzE1NDM2MjU5MTkwNDIiLCI2OTY1MzI0OTI3MDYzMDQxOTU2NTIwODg5ODU1MDcxNjU1OTg5Mzg4NzQyODM1ODgzOTI1NjU4MDI1NDE0MjM4OTQ2OTkxNjE1ODMwIiwiMSJdLCJwaV9iIjpbWyIxNjgwMjkyNTc5OTM3NjI4MDExOTc1MTk2MTk1MDEzNjQ5NjkyMjMyOTU1NDI5Mjc0Nzc5OTE1NDI2MDQwMzMwNTM0Njc1NDU1Mzk5NCIsIjIwNzkzNDcyNDAwMzczNDkzMjIyNzAyNDY4NDcxMjQzNzcwMzk3NzY1MzY0OTc3NDA0NDQwNTQ2Mzc0MTkxNjU2OTM0NDE3Mjg1MDQxIl0sWyI2MTI1MjcxNjYyOTI4NDUzMjQ5NDgyMjc5MjQ2ODA2NTIxNTE2MzU5NDQwMTcxMDM1MzgxMzU4OTI3MjI4Njc2NTQxNTc0NTg5MDkxIiwiNTY4MDc3OTcxNTc0MjMyMjI0ODQyOTM0NDc1ODA5NDk0MzMyMzE1OTIzOTQzNjkyNzI3MjM3NDEwOTkxMzYzOTAyMjM2NDMyMjYwNiJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTQ4MTkzNTE5MTMwNTA0OTM5MTA3MjkxMDkxNzE2ODQzNzA0OTI4MjQyMzc3NDQ5MDM4NzMwNDU3NzM3MTI4Mjc0Mjc1NTc3ODYwOCIsIjEyMDMxNDE1NjE1ODExNTEzNzc2OTcwMDYwOTgzMDk2NTMxNzcwMTcwNDAxMjkzODEwMTQwMDY2ODM1NzkyMjk4NTcwNDQxMzcyMTg3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMTQ4OTM2NDY2MzM0MzUwNzQ0NTQ4NzkwMDEyMjk0NDg5MzY1MjA3NDQwNzU0NTA5OTg4OTg2Njg0Nzk3NzA4MzcwMDUxMDczIiwiNjExMDUxNzc2ODI0OTU1OTIzODE5MzQ3NzQzNTQ1NDc5MjAyNDczMjE3Mzg2NTQ4ODkwMDI3MDg0OTYyNDMyODY1MDc2NTY5MTQ5NCIsIjEyNDM5MDQ3MTE0Mjk5NjE4NTg3NzQyMjA2NDc2MTA3MjQyNzM3OTg5MTg0NTc5OTE0ODYwMzE1NjcyNDQxMDA3NjcyNTkyMzk3NDciXX0';

describe('IIFE build (window.JWZ)', () => {
  test('exposes expected exports', () => {
    expect(JWZ).toBeDefined();
    expect(typeof JWZ.Token).toBe('function');
    expect(typeof JWZ.hash).toBe('function');
    expect(typeof JWZ.verifyGroth16Proof).toBe('function');
    expect(JWZ.proving).toBeDefined();
  });

  test('parse token and verify', async () => {
    const verificationKey = await fetch(VERIFICATION_KEY_URL).then((r) => r.arrayBuffer());
    const token: InstanceType<typeof TokenType> = await JWZ.Token.parse(JWZ_TOKEN);

    expect(token.circuitId).toBe('authV2');
    expect(token.alg).toBe('groth16');

    const isValid = await token.verify(verificationKey as unknown as Uint8Array);
    expect(isValid).toBe(true);
  });
});
