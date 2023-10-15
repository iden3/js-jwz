import { hash } from './hash';
import {
  ZKProof,
  ProvingMethod,
  ProvingMethodAlg,
  ProofInputsPreparerHandlerFunc,
  getProvingMethod,
  prepare
} from './proving';

import { base64url as base64 } from 'rfc4648';
import { toBigEndian } from '@iden3/js-iden3-core';

export enum Header {
  Type = 'typ',
  Alg = 'alg',
  CircuitId = 'circuitId',
  Critical = 'crit'
}

export interface IRawJSONWebZeroknowledge {
  payload: Uint8Array;
  protectedHeaders: Uint8Array;
  header: { [key: string]: unknown };
  zkp: Uint8Array;

  sanitized(): Promise<Token>;
}

export class RawJSONWebZeroknowledge implements IRawJSONWebZeroknowledge {
  constructor(
    public payload: Uint8Array,
    public protectedHeaders: Uint8Array,
    public header: { [key: string]: unknown },
    public zkp: Uint8Array
  ) {}

  async sanitized(): Promise<Token> {
    if (!this.payload) {
      throw new Error('iden3/js-jwz: missing payload in JWZ message');
    }

    const headers: { [key: string]: unknown } = JSON.parse(
      new TextDecoder().decode(this.protectedHeaders)
    );
    const criticalHeaders = headers[Header.Critical] as string[];
    criticalHeaders.forEach((key: string) => {
      if (!headers[key]) {
        throw new Error(`iden3/js-jwz: header is listed in critical ${key}, but not presented`);
      }
    });

    const alg = headers[Header.Alg] as string;
    const circuitId = headers[Header.CircuitId] as string;

    const method = await getProvingMethod(new ProvingMethodAlg(alg, circuitId));
    const zkp = JSON.parse(new TextDecoder().decode(this.zkp));
    const token = new Token(method, new TextDecoder().decode(this.payload));
    token.alg = alg;
    token.circuitId = circuitId;
    token.zkProof = zkp;
    for (const [key, value] of Object.entries(headers)) {
      token.setHeader(key, value);
    }

    return token;
  }
}

// Token represents a JWZ Token.
export class Token {
  public alg: string;
  public circuitId: string;
  private raw: IRawJSONWebZeroknowledge;
  public zkProof: ZKProof = {} as ZKProof;

  constructor(
    public readonly method: ProvingMethod,
    payload: string,
    private readonly inputsPreparer?: ProofInputsPreparerHandlerFunc
  ) {
    this.alg = this.method.alg;
    this.circuitId = this.method.circuitId;
    this.raw = {} as IRawJSONWebZeroknowledge;
    this.raw.header = this.getDefaultHeaders();

    this.raw.payload = new TextEncoder().encode(payload);
  }

  public setHeader(key: string, value: unknown): void {
    this.raw.header[key] = value;
  }

  public getPayload(): string {
    return new TextDecoder().decode(this.raw.payload);
  }

  private getDefaultHeaders(): { [key: string]: string | string[] } {
    return {
      [Header.Alg]: this.alg,
      [Header.Critical]: [Header.CircuitId],
      [Header.CircuitId]: this.circuitId,
      [Header.Type]: 'JWZ'
    };
  }

  // Parse parses a jwz message in compact or full serialization format.
  static parse(tokenStr: string): Promise<Token> {
    // Parse parses a jwz message in compact or full serialization format.
    const token = tokenStr?.trim();
    return token.startsWith('{') ? Token.parseFull(tokenStr) : Token.parseCompact(tokenStr);
  }

  // parseCompact parses a message in compact format.
  private static async parseCompact(tokenStr: string): Promise<Token> {
    const parts = tokenStr.split('.');
    if (parts.length != 3) {
      throw new Error('iden3/js-jwz: compact JWZ format must have three segments');
    }
    const rawProtected = base64.parse(parts[0], { loose: true });

    const rawPayload = base64.parse(parts[1], { loose: true });

    const proof = base64.parse(parts[2], { loose: true });

    const raw: IRawJSONWebZeroknowledge = new RawJSONWebZeroknowledge(
      rawPayload,
      rawProtected,
      {},
      proof
    );

    return await raw.sanitized();
  }

  // parseFull parses a message in full format.
  private static async parseFull(tokenStr: string): Promise<Token> {
    const raw: IRawJSONWebZeroknowledge = JSON.parse(tokenStr);
    return await raw.sanitized();
  }

  // Prove creates and returns a complete, proved JWZ.
  // The token is proven using the Proving Method specified in the token.
  async prove(provingKey: Uint8Array, wasm: Uint8Array): Promise<string> {
    // all headers must be protected
    const headers = this.serializeHeaders();

    this.raw.protectedHeaders = new TextEncoder().encode(headers);

    const msgHash: Uint8Array = await this.getMessageHash();

    if (!this.inputsPreparer) {
      throw new Error('iden3/jwz: prepare func must be defined');
    }
    const inputs: Uint8Array = await prepare(this.inputsPreparer, msgHash, this.circuitId);

    const proof: ZKProof = await this.method.prove(inputs, provingKey, wasm);

    const marshaledProof = JSON.stringify(proof);

    this.zkProof = proof;
    this.raw.zkp = new TextEncoder().encode(marshaledProof);

    return this.compactSerialize();
  }

  // CompactSerialize returns token serialized in three parts: base64 encoded headers, payload and proof.
  compactSerialize(): string {
    if (!this.raw.header || !this.raw.protectedHeaders || !this.zkProof) {
      throw new Error("iden3/jwz:can't serialize without one of components");
    }

    const serializedProtected = base64.stringify(this.raw.protectedHeaders, {
      pad: false
    });
    const serializedProof = base64.stringify(this.raw.zkp, { pad: false });
    const serializedPayload = base64.stringify(this.raw.payload, {
      pad: false
    });
    return `${serializedProtected}.${serializedPayload}.${serializedProof}`;
  }

  // fullSerialize returns marshaled presentation of raw token as json string.
  fullSerialize(): string {
    return JSON.stringify(this.raw);
  }

  async getMessageHash(): Promise<Uint8Array> {
    const serializedHeadersJSON = this.serializeHeaders();

    const serializedHeaders = new TextEncoder().encode(serializedHeadersJSON);
    const protectedHeaders = base64.stringify(serializedHeaders, {
      pad: false
    });

    const payload = base64.stringify(this.raw.payload, { pad: false });

    // JWZ ZkProof input value is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
    const messageToProof = new TextEncoder().encode(`${protectedHeaders}.${payload}`);

    const hashInt: bigint = await hash(messageToProof);

    return toBigEndian(hashInt, 32);
  }

  // Verify  perform zero knowledge verification.
  async verify(verificationKey: Uint8Array): Promise<boolean> {
    // 1. prepare hash o payload message that had to be proven
    const msgHash = await this.getMessageHash();

    // 2. verify that zkp is valid

    return this.method.verify(msgHash, this.zkProof, verificationKey);
  }

  serializeHeaders() {
    return JSON.stringify(this.raw.header, Object.keys(this.raw.header).sort());
  }
}
