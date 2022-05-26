import { toLittleEndian } from './core/util';
import { hash } from './hash';
import {
  ZKProof,
  ProvingMethod,
  ProofInputsPreparerHandlerFunc,
  getProvingMethod,
  prepare,
} from './proving';

// HeaderType is 'typ' header, so we can set specific typ
export const HeaderType = 'typ'; // we allow to set typ of token
export const headerCritical = 'crit';
export const headerAlg = 'alg';
export const headerCircuitId = 'circuitId';

export interface IRawJSONWebZeroknowledge {
  payload: string;
  protectedHeaders: string;
  header: { [key: string]: any };
  zkp: string;

  sanitized(): Promise<Token>;
}

export class RawJSONWebZeroknowledge implements IRawJSONWebZeroknowledge {
  constructor(
    public payload: string,
    public protectedHeaders: string,
    public header: { [key: string]: any },
    public zkp: string,
  ) {}

  async sanitized(): Promise<Token> {
    if (!this.payload) {
      throw new Error('iden3/go-jwz: missing payload in JWZ message');
    }
    const headers = JSON.parse(this.protectedHeaders);
    const criticalHeaders = headers[headerCritical];

    Object.keys(criticalHeaders).forEach((k) => {
      if (!headers[k]) {
        throw new Error(
          `iden3/go-jwz: header is listed in critical ${key}, but not presented`,
        );
      }
    });

    const alg = headers[headerAlg];
    const method = await getProvingMethod(headers[headerAlg]);
    const circuitId = headers[headerCircuitId];
    const zkp = JSON.parse(this.zkp);
    const token = new Token(method, this.payload, () => Uint8Array.from([]));
    token.alg = alg;
    token.circuitId = circuitId;
    token.zkProof = zkp;

    return token;
  }
}

// Token represents a JWZ Token.
export class Token {
  public alg: string;
  public circuitId: string;
  public raw: IRawJSONWebZeroknowledge;
  public zkProof: ZKProof = {} as ZKProof;

  constructor(
    public readonly method: ProvingMethod,
    payload: string,
    private readonly inputsPreparer: ProofInputsPreparerHandlerFunc,
  ) {
    this.alg = this.method.alg;
    this.circuitId = this.method.circuitId;
    this.raw = {} as IRawJSONWebZeroknowledge;
    this.raw.header = this.getDefaultHeaders();
    this.raw.payload = payload;
  }

  public setHeader(key: string, value: unknown): void {
    this.raw.header[key] = value;
  }

  public getPayload(): string {
    return this.raw.payload;
  }

  public setPayload(payload: string): void {
    this.raw.payload = payload;
  }

  private getDefaultHeaders(): { [key: string]: string | string[] } {
    return {
      headerAlg: this.alg,
      headerCritical: [headerCircuitId],
      headerCircuitID: this.circuitId,
      HeaderType: 'JWZ',
    };
  }

  // Parse parses a jwz message in compact or full serialization format.
  parse(tokenStr: string): Promise<Token> {
    // Parse parses a jwz message in compact or full serialization format.
    const token = tokenStr?.trim();
    return token.startsWith('{')
      ? this.parseFull(tokenStr)
      : this.parseCompact(tokenStr);
  }

  // parseCompact parses a message in compact format.
  private async parseCompact(tokenStr: string): Promise<Token> {
    const parts = tokenStr.split('.');
    if (parts.length != 3) {
      throw new Error(
        'iden3/go-jwz: compact JWZ format must have three segments',
      );
    }
    const rawProtected = atob(parts[0]);

    const rawPayload = atob(parts[1]);

    const proof = atob(parts[2]);

    const raw: IRawJSONWebZeroknowledge = new RawJSONWebZeroknowledge(
      rawPayload,
      rawProtected,
      {},
      proof,
    );

    return await raw.sanitized();
  }

  // parseFull parses a message in full format.
  private async parseFull(tokenStr: string): Promise<Token> {
    const raw: IRawJSONWebZeroknowledge = JSON.parse(tokenStr);
    return await raw.sanitized();
  }
  // ParsePubSignals unmarshalls proof public signals to provided structure.
  parsePubSignals(out: {
    pubSignalsUnmarshal: (data: string) => unknown;
  }): unknown {
    const pubSignals = JSON.parse(this.zkProof.pub_signals);

    out.pubSignalsUnmarshal(pubSignals);

    return null;
  }

  // Prove creates and returns a complete, proved JWZ.
  // The token is proven using the Proving Method specified in the token.
  prove(provingKey: Uint8Array, wasm: Uint8Array): string {
    // all headers must be protected
    const headers = JSON.stringify(this.raw.header);

    this.raw.protectedHeaders = headers;

    const msgHash: Uint8Array = this.getMessageHash();

    const inputs: Uint8Array = prepare(
      this.inputsPreparer,
      msgHash,
      this.circuitId,
    );

    const proof: ZKProof = this.method.prove(inputs, provingKey, wasm);

    const marshaledProof = JSON.stringify(proof);

    this.zkProof = proof;
    this.raw.zkp = marshaledProof;

    return this.compactSerialize();
  }

  // CompactSerialize returns token serialized in three parts: base64 encoded headers, payload and proof.
  compactSerialize(): string {
    if (!this.raw.header || !this.raw.protectedHeaders || !this.zkProof) {
      throw new Error("iden3/jwz:can't serialize without one of components");
    }

    const serializedProtected = atob(this.raw.protectedHeaders);
    const serializedProof = atob(JSON.stringify(this.zkProof));
    const serializedPayload = atob(this.raw.payload);

    return `${serializedProtected}.${serializedPayload}.${serializedProof}`;
  }

  // FullSerialize returns marshaled presentation of raw token as json string.
  fullSerialize(): string {
    return JSON.stringify(this.raw);
  }

  async getMessageHash(): Promise<Uint8Array> {
    const headers = JSON.stringify(this.raw.header);

    const protectedHeaders = btoa(headers);
    const payload = btoa(this.raw.payload);

    // JWZ ZkProof input value is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
    const messageToProof = new TextEncoder().encode(
      `${protectedHeaders}.${payload}`,
    );

    const hashInt: bigint = await hash(messageToProof);
    return toLittleEndian(hashInt);
  }
}
