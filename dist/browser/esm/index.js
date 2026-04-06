import { Id, fromBigEndian, toBigEndian } from "@iden3/js-iden3-core";
import { poseidon, sha256 } from "@iden3/js-crypto";
import { base64url } from "rfc4648";
import { groth16 } from "snarkjs";
import { Hash } from "@iden3/js-merkletree";
import { getCurveFromName } from "ffjavascript";
//#region src/hash.ts
var qString = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
function hash(message) {
	const bi = fromBigEndian(sha256(message).reverse());
	let m = BigInt(0);
	if (checkBigIntInField(bi)) m = bi;
	else m = bi % BigInt(qString);
	return poseidon.hash([m]);
}
function checkBigIntInField(a) {
	return a < BigInt(qString);
}
//#endregion
//#region src/proving.ts
var ProvingMethodAlg = class {
	constructor(alg, circuitId) {
		this.alg = alg;
		this.circuitId = circuitId;
	}
	toString() {
		return `${this.alg}:${this.circuitId}`;
	}
};
var provingMethods = /* @__PURE__ */ new Map();
function registerProvingMethod(alg, f) {
	return new Promise((res) => {
		provingMethods.set(alg.toString(), f);
		res();
	});
}
function getProvingMethod(alg) {
	return new Promise((res, rej) => {
		const func = provingMethods.get(alg.toString());
		if (func) res(func());
		else rej("unknown alg");
	});
}
//#endregion
//#region src/jwz.ts
var Header = /* @__PURE__ */ function(Header) {
	Header["Type"] = "typ";
	Header["Alg"] = "alg";
	Header["CircuitId"] = "circuitId";
	Header["Critical"] = "crit";
	return Header;
}({});
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var RawJSONWebZeroknowledge = class {
	constructor(payload, protectedHeaders, header, zkp) {
		this.payload = payload;
		this.protectedHeaders = protectedHeaders;
		this.header = header;
		this.zkp = zkp;
	}
	async sanitized() {
		if (!this.payload) throw new Error("iden3/js-jwz: missing payload in JWZ message");
		const headers = JSON.parse(decoder.decode(this.protectedHeaders));
		headers[Header.Critical].forEach((key) => {
			if (!headers[key]) throw new Error(`iden3/js-jwz: header is listed in critical ${key}, but not presented`);
		});
		const alg = headers[Header.Alg];
		const circuitId = headers[Header.CircuitId];
		const method = await getProvingMethod(new ProvingMethodAlg(alg, circuitId));
		const zkp = JSON.parse(decoder.decode(this.zkp));
		const token = new Token(method, decoder.decode(this.payload));
		token.alg = alg;
		token.circuitId = circuitId;
		token.zkProof = zkp;
		for (const [key, value] of Object.entries(headers)) token.setHeader(key, value);
		return token;
	}
};
var Token = class Token {
	alg;
	circuitId;
	raw;
	zkProof = {};
	constructor(method, payload, inputsPreparer) {
		this.method = method;
		this.inputsPreparer = inputsPreparer;
		this.alg = this.method.alg;
		this.circuitId = this.method.circuitId;
		this.raw = {};
		this.raw.header = this.getDefaultHeaders();
		this.raw.payload = encoder.encode(payload);
	}
	setHeader(key, value) {
		this.raw.header[key] = value;
	}
	getPayload() {
		return decoder.decode(this.raw.payload);
	}
	getDefaultHeaders() {
		return {
			[Header.Alg]: this.alg,
			[Header.Critical]: [Header.CircuitId],
			[Header.CircuitId]: this.circuitId,
			[Header.Type]: "JWZ"
		};
	}
	static parse(tokenStr) {
		return (tokenStr?.trim()).startsWith("{") ? Token.parseFull(tokenStr) : Token.parseCompact(tokenStr);
	}
	static async parseCompact(tokenStr) {
		const parts = tokenStr.split(".");
		if (parts.length != 3) throw new Error("iden3/js-jwz: compact JWZ format must have three segments");
		const rawProtected = base64url.parse(parts[0], { loose: true });
		return await new RawJSONWebZeroknowledge(base64url.parse(parts[1], { loose: true }), rawProtected, {}, base64url.parse(parts[2], { loose: true })).sanitized();
	}
	static async parseFull(tokenStr) {
		return await JSON.parse(tokenStr).sanitized();
	}
	async prove(provingKey, wasm) {
		const headers = this.serializeHeaders();
		this.raw.protectedHeaders = encoder.encode(headers);
		const msgHash = await this.getMessageHash();
		if (!this.inputsPreparer) throw new Error("iden3/jwz: prepare func must be defined");
		const inputs = await this.inputsPreparer(msgHash, this.circuitId);
		const proof = await this.method.prove(inputs, provingKey, wasm);
		const marshaledProof = JSON.stringify(proof);
		this.zkProof = proof;
		this.raw.zkp = encoder.encode(marshaledProof);
		return this.compactSerialize();
	}
	async dynamicProve(dynamicProvingParams) {
		const headers = this.serializeHeaders();
		this.raw.protectedHeaders = encoder.encode(headers);
		const msgHash = await this.getMessageHash();
		if (!dynamicProvingParams.inputsPreparerFn) throw new Error("iden3/jwz: prepare func must be defined");
		const result = await dynamicProvingParams.inputsPreparerFn(msgHash, this.circuitId);
		const targetCircuitId = "targetCircuitId" in result ? result.targetCircuitId : this.circuitId;
		const provingParams = dynamicProvingParams.provingParams.find((p) => p.circuitId === targetCircuitId);
		const inputs = "inputs" in result ? result.inputs : result;
		if (!provingParams) throw new Error("iden3/jwz: proving params not found for circuit id");
		if (!this.method.supportedCircuits.includes(targetCircuitId)) throw new Error(`iden3/jwz: ${targetCircuitId} is not supported. Valid circuitIds: ${this.method.supportedCircuits.join(", ")}`);
		const proof = await this.method.prove(inputs, provingParams.provingKey, provingParams.wasm);
		proof.proof.protocol = `${proof.proof.protocol};${targetCircuitId}`;
		const marshaledProof = JSON.stringify(proof);
		this.zkProof = proof;
		this.raw.zkp = encoder.encode(marshaledProof);
		return this.compactSerialize();
	}
	compactSerialize() {
		if (!this.raw.header || !this.raw.protectedHeaders || !this.zkProof) throw new Error("iden3/jwz:can't serialize without one of components");
		const serializedProtected = base64url.stringify(this.raw.protectedHeaders, { pad: false });
		const serializedProof = base64url.stringify(this.raw.zkp, { pad: false });
		return `${serializedProtected}.${base64url.stringify(this.raw.payload, { pad: false })}.${serializedProof}`;
	}
	fullSerialize() {
		return JSON.stringify(this.raw);
	}
	async getMessageHash() {
		const serializedHeadersJSON = this.serializeHeaders();
		const serializedHeaders = encoder.encode(serializedHeadersJSON);
		const protectedHeaders = base64url.stringify(serializedHeaders, { pad: false });
		const payload = base64url.stringify(this.raw.payload, { pad: false });
		return toBigEndian(hash(encoder.encode(`${protectedHeaders}.${payload}`)), 32);
	}
	async verify(verificationKey) {
		const msgHash = await this.getMessageHash();
		return this.method.verify(msgHash, this.zkProof, verificationKey);
	}
	async dynamicVerify(dynamicVerificationParams) {
		const msgHash = await this.getMessageHash();
		const targetCircuitId = this.zkProof.proof.protocol.split(";")[1] ?? this.circuitId;
		if (!this.method.supportedCircuits.includes(targetCircuitId)) throw new Error(`iden3/jwz: ${targetCircuitId} is not supported. Valid circuitIds: ${this.method.supportedCircuits.join(", ")}`);
		const verificationKeyMap = dynamicVerificationParams.verificationKeysMap.find((p) => p.circuitId === targetCircuitId);
		if (!verificationKeyMap) throw new Error(`iden3/jwz: verification key map not found for circuit id ${targetCircuitId}`);
		return this.method.verify(msgHash, this.zkProof, verificationKeyMap.verificationKey);
	}
	serializeHeaders() {
		return JSON.stringify(this.raw.header, Object.keys(this.raw.header).sort());
	}
};
//#endregion
//#region src/witness_calculator.ts
async function witnessBuilder(code, options) {
	options = options || {};
	let wasmModule;
	try {
		wasmModule = await WebAssembly.compile(code);
	} catch (err) {
		throw new Error(err);
	}
	let errStr = "";
	let msgStr = "";
	const instance = await WebAssembly.instantiate(wasmModule, { runtime: {
		exceptionHandler: function(code) {
			let err;
			if (code == 1) err = "Signal not found.\n";
			else if (code == 2) err = "Too many signals set.\n";
			else if (code == 3) err = "Signal already set.\n";
			else if (code == 4) err = "Assert Failed.\n";
			else if (code == 5) err = "Not enough memory.\n";
			else if (code == 6) err = "Input signal array access exceeds the size.\n";
			else err = "Unknown error.\n";
			throw new Error(err + errStr);
		},
		printErrorMessage: function() {
			errStr += getMessage() + "\n";
		},
		writeBufferMessage: function() {
			const msg = getMessage();
			if (msg === "\n") msgStr = "";
			else {
				if (msgStr !== "") msgStr += " ";
				msgStr += msg;
			}
		},
		showSharedRWMemory: function() {
			printSharedRWMemory();
		}
	} });
	return new WitnessCalculator(instance, options);
	function getMessage() {
		let message = "";
		let c = instance.exports.getMessageChar();
		while (c != 0) {
			message += String.fromCharCode(c);
			c = instance.exports.getMessageChar();
		}
		return message;
	}
	function printSharedRWMemory() {
		const shared_rw_memory_size = instance.exports.getFieldNumLen32();
		const arr = new Uint32Array(shared_rw_memory_size);
		for (let j = 0; j < shared_rw_memory_size; j++) arr[shared_rw_memory_size - 1 - j] = instance.exports.readSharedRWMemory(j);
		if (msgStr !== "") msgStr += " ";
		msgStr += fromArray32(arr).toString();
	}
}
var WitnessCalculator = class {
	version;
	n32;
	prime;
	witnessSize;
	sanityCheck;
	constructor(instance, sanityCheck) {
		this.instance = instance;
		this.instance = instance;
		this.version = this.instance.exports.getVersion();
		this.n32 = this.instance.exports.getFieldNumLen32();
		this.instance.exports.getRawPrime();
		const arr = new Uint32Array(this.n32);
		for (let i = 0; i < this.n32; i++) arr[this.n32 - 1 - i] = this.instance.exports.readSharedRWMemory(i);
		this.prime = fromArray32(arr);
		this.witnessSize = this.instance.exports.getWitnessSize();
		this.sanityCheck = sanityCheck;
	}
	circom_version() {
		return this.instance.exports.getVersion();
	}
	async _doCalculateWitness(input, sanityCheck) {
		this.instance.exports.init(this.sanityCheck || sanityCheck ? 1 : 0);
		const keys = Object.keys(input);
		let input_counter = 0;
		keys.forEach((k) => {
			const h = fnvHash(k);
			const hMSB = parseInt(h.slice(0, 8), 16);
			const hLSB = parseInt(h.slice(8, 16), 16);
			const fArr = flatArray(input[k]);
			const signalSize = this.instance.exports.getInputSignalSize(hMSB, hLSB);
			if (signalSize < 0) throw new Error(`Signal ${k} not found\n`);
			if (fArr.length < signalSize) throw new Error(`Not enough values for input signal ${k}\n`);
			if (fArr.length > signalSize) throw new Error(`Too many values for input signal ${k}\n`);
			for (let i = 0; i < fArr.length; i++) {
				const arrFr = toArray32(BigInt(fArr[i]) % this.prime, this.n32);
				for (let j = 0; j < this.n32; j++) this.instance.exports.writeSharedRWMemory(j, arrFr[this.n32 - 1 - j]);
				try {
					this.instance.exports.setInputSignal(hMSB, hLSB, i);
					input_counter++;
				} catch (err) {
					throw new Error(err);
				}
			}
		});
		if (input_counter < this.instance.exports.getInputSize()) throw new Error(`Not all inputs have been set. Only ${input_counter} out of ${this.instance.exports.getInputSize()}`);
	}
	async calculateWitness(input, sanityCheck) {
		const w = [];
		await this._doCalculateWitness(input, sanityCheck);
		for (let i = 0; i < this.witnessSize; i++) {
			this.instance.exports.getWitness(i);
			const arr = new Uint32Array(this.n32);
			for (let j = 0; j < this.n32; j++) arr[this.n32 - 1 - j] = this.instance.exports.readSharedRWMemory(j);
			w.push(fromArray32(arr));
		}
		return w;
	}
	async calculateBinWitness(input, sanityCheck) {
		const buff32 = new Uint32Array(this.witnessSize * this.n32);
		const buff = new Uint8Array(buff32.buffer);
		await this._doCalculateWitness(input, sanityCheck);
		for (let i = 0; i < this.witnessSize; i++) {
			this.instance.exports.getWitness(i);
			const pos = i * this.n32;
			for (let j = 0; j < this.n32; j++) buff32[pos + j] = this.instance.exports.readSharedRWMemory(j);
		}
		return buff;
	}
	async calculateWTNSBin(input, sanityCheck) {
		const buff32 = new Uint32Array(this.witnessSize * this.n32 + this.n32 + 11);
		const buff = new Uint8Array(buff32.buffer);
		await this._doCalculateWitness(input, sanityCheck);
		buff[0] = "w".charCodeAt(0);
		buff[1] = "t".charCodeAt(0);
		buff[2] = "n".charCodeAt(0);
		buff[3] = "s".charCodeAt(0);
		buff32[1] = 2;
		buff32[2] = 2;
		buff32[3] = 1;
		const n8 = this.n32 * 4;
		const idSection1lengthHex = (8 + n8).toString(16);
		buff32[4] = parseInt(idSection1lengthHex.slice(0, 8), 16);
		buff32[5] = parseInt(idSection1lengthHex.slice(8, 16), 16);
		buff32[6] = n8;
		this.instance.exports.getRawPrime();
		let pos = 7;
		for (let j = 0; j < this.n32; j++) buff32[pos + j] = this.instance.exports.readSharedRWMemory(j);
		pos += this.n32;
		buff32[pos] = this.witnessSize;
		pos++;
		buff32[pos] = 2;
		pos++;
		const idSection2lengthHex = (n8 * this.witnessSize).toString(16);
		buff32[pos] = parseInt(idSection2lengthHex.slice(0, 8), 16);
		buff32[pos + 1] = parseInt(idSection2lengthHex.slice(8, 16), 16);
		pos += 2;
		for (let i = 0; i < this.witnessSize; i++) {
			this.instance.exports.getWitness(i);
			for (let j = 0; j < this.n32; j++) buff32[pos + j] = this.instance.exports.readSharedRWMemory(j);
			pos += this.n32;
		}
		return buff;
	}
};
function toArray32(rem, size) {
	const res = [];
	const radix = BigInt(4294967296);
	while (rem) {
		res.unshift(Number(rem % radix));
		rem = rem / radix;
	}
	if (size) {
		let i = size - res.length;
		while (i > 0) {
			res.unshift(0);
			i--;
		}
	}
	return res;
}
function fromArray32(arr) {
	let res = BigInt(0);
	const radix = BigInt(4294967296);
	for (let i = 0; i < arr.length; i++) res = res * radix + BigInt(arr[i]);
	return res;
}
function flatArray(a) {
	const res = [];
	fillArray(res, a);
	return res;
	function fillArray(res, a) {
		if (Array.isArray(a)) for (let i = 0; i < a.length; i++) fillArray(res, a[i]);
		else res.push(a);
	}
}
function fnvHash(str) {
	const uint64_max = BigInt(2) ** BigInt(64);
	let hash = BigInt("0xCBF29CE484222325");
	for (let i = 0; i < str.length; i++) {
		hash ^= BigInt(str[i].charCodeAt());
		hash *= BigInt(1099511628211);
		hash %= uint64_max;
	}
	let hashHex = hash.toString(16);
	const n = 16 - hashHex.length;
	hashHex = "0".repeat(n).concat(hashHex);
	return hashHex;
}
//#endregion
//#region node_modules/@noble/hashes/utils.js
/**
* Utilities for hex, bytes, CSPRNG.
* @module
*/
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function isBytes(a) {
	return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
/** Asserts something is positive integer. */
function anumber(n, title = "") {
	if (!Number.isSafeInteger(n) || n < 0) {
		const prefix = title && `"${title}" `;
		throw new Error(`${prefix}expected integer >= 0, got ${n}`);
	}
}
/** Asserts something is Uint8Array. */
function abytes(value, length, title = "") {
	const bytes = isBytes(value);
	const len = value?.length;
	const needsLen = length !== void 0;
	if (!bytes || needsLen && len !== length) {
		const prefix = title && `"${title}" `;
		const ofLen = needsLen ? ` of length ${length}` : "";
		const got = bytes ? `length=${len}` : `type=${typeof value}`;
		throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
	}
	return value;
}
new Uint8Array(new Uint32Array([287454020]).buffer)[0];
var hasHexBuiltin = typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function";
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
/**
* Convert byte array to hex string. Uses built-in function, when available.
* @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
*/
function bytesToHex(bytes) {
	abytes(bytes);
	if (hasHexBuiltin) return bytes.toHex();
	let hex = "";
	for (let i = 0; i < bytes.length; i++) hex += hexes[bytes[i]];
	return hex;
}
var asciis = {
	_0: 48,
	_9: 57,
	A: 65,
	F: 70,
	a: 97,
	f: 102
};
function asciiToBase16(ch) {
	if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0;
	if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10);
	if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10);
}
/**
* Convert hex string to byte array. Uses built-in function, when available.
* @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
*/
function hexToBytes(hex) {
	if (typeof hex !== "string") throw new Error("hex string expected, got " + typeof hex);
	if (hasHexBuiltin) return Uint8Array.fromHex(hex);
	const hl = hex.length;
	const al = hl / 2;
	if (hl % 2) throw new Error("hex string expected, got unpadded hex of length " + hl);
	const array = new Uint8Array(al);
	for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
		const n1 = asciiToBase16(hex.charCodeAt(hi));
		const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
		if (n1 === void 0 || n2 === void 0) {
			const char = hex[hi] + hex[hi + 1];
			throw new Error("hex string expected, got non-hex character \"" + char + "\" at index " + hi);
		}
		array[ai] = n1 * 16 + n2;
	}
	return array;
}
/** Copies several Uint8Arrays into one. */
function concatBytes(...arrays) {
	let sum = 0;
	for (let i = 0; i < arrays.length; i++) {
		const a = arrays[i];
		abytes(a);
		sum += a.length;
	}
	const res = new Uint8Array(sum);
	for (let i = 0, pad = 0; i < arrays.length; i++) {
		const a = arrays[i];
		res.set(a, pad);
		pad += a.length;
	}
	return res;
}
/** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
function randomBytes(bytesLength = 32) {
	const cr = typeof globalThis === "object" ? globalThis.crypto : null;
	if (typeof cr?.getRandomValues !== "function") throw new Error("crypto.getRandomValues must be defined");
	return cr.getRandomValues(new Uint8Array(bytesLength));
}
//#endregion
//#region node_modules/@noble/curves/utils.js
/**
* Hex, bytes and number utilities.
* @module
*/
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n$6 = /* @__PURE__ */ BigInt(0);
var _1n$6 = /* @__PURE__ */ BigInt(1);
function abool(value, title = "") {
	if (typeof value !== "boolean") {
		const prefix = title && `"${title}" `;
		throw new Error(prefix + "expected boolean, got type=" + typeof value);
	}
	return value;
}
function abignumber(n) {
	if (typeof n === "bigint") {
		if (!isPosBig(n)) throw new Error("positive bigint expected, got " + n);
	} else anumber(n);
	return n;
}
function hexToNumber(hex) {
	if (typeof hex !== "string") throw new Error("hex string expected, got " + typeof hex);
	return hex === "" ? _0n$6 : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
	return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
	return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
}
function numberToBytesBE(n, len) {
	anumber(len);
	n = abignumber(n);
	const res = hexToBytes(n.toString(16).padStart(len * 2, "0"));
	if (res.length !== len) throw new Error("number too large");
	return res;
}
function numberToBytesLE(n, len) {
	return numberToBytesBE(n, len).reverse();
}
/**
* Copies Uint8Array. We can't use u8a.slice(), because u8a can be Buffer,
* and Buffer#slice creates mutable copy. Never use Buffers!
*/
function copyBytes(bytes) {
	return Uint8Array.from(bytes);
}
var isPosBig = (n) => typeof n === "bigint" && _0n$6 <= n;
/**
* Calculates amount of bits in a bigint.
* Same as `n.toString(2).length`
* TODO: merge with nLength in modular
*/
function bitLen(n) {
	let len;
	for (len = 0; n > _0n$6; n >>= _1n$6, len += 1);
	return len;
}
/**
* Gets single bit at position.
* NOTE: first bit position is 0 (same as arrays)
* Same as `!!+Array.from(n.toString(2)).reverse()[pos]`
*/
function bitGet(n, pos) {
	return n >> BigInt(pos) & _1n$6;
}
/**
* Calculate mask for N bits. Not using ** operator with bigints because of old engines.
* Same as BigInt(`0b${Array(i).fill('1').join('')}`)
*/
var bitMask = (n) => (_1n$6 << BigInt(n)) - _1n$6;
function validateObject(object, fields = {}, optFields = {}) {
	if (!object || typeof object !== "object") throw new Error("expected valid options object");
	function checkField(fieldName, expectedType, isOpt) {
		const val = object[fieldName];
		if (isOpt && val === void 0) return;
		const current = typeof val;
		if (current !== expectedType || val === null) throw new Error(`param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`);
	}
	const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
	iter(fields, false);
	iter(optFields, true);
}
/**
* throws not implemented error
*/
var notImplemented = () => {
	throw new Error("not implemented");
};
/**
* Memoizes (caches) computation result.
* Uses WeakMap: the value is going auto-cleaned by GC after last reference is removed.
*/
function memoized(fn) {
	const map = /* @__PURE__ */ new WeakMap();
	return (arg, ...args) => {
		const val = map.get(arg);
		if (val !== void 0) return val;
		const computed = fn(arg, ...args);
		map.set(arg, computed);
		return computed;
	};
}
//#endregion
//#region node_modules/@noble/curves/abstract/modular.js
/**
* Utils for modular division and fields.
* Field over 11 is a finite (Galois) field is integer number operations `mod 11`.
* There is no division: it is replaced by modular multiplicative inverse.
* @module
*/
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n$5 = /* @__PURE__ */ BigInt(0), _1n$5 = /* @__PURE__ */ BigInt(1), _2n$4 = /* @__PURE__ */ BigInt(2);
var _3n$4 = /* @__PURE__ */ BigInt(3), _4n$1 = /* @__PURE__ */ BigInt(4), _5n = /* @__PURE__ */ BigInt(5);
var _7n = /* @__PURE__ */ BigInt(7), _8n = /* @__PURE__ */ BigInt(8), _9n = /* @__PURE__ */ BigInt(9);
var _16n = /* @__PURE__ */ BigInt(16);
function mod(a, b) {
	const result = a % b;
	return result >= _0n$5 ? result : b + result;
}
/**
* Inverses number over modulo.
* Implemented using [Euclidean GCD](https://brilliant.org/wiki/extended-euclidean-algorithm/).
*/
function invert(number, modulo) {
	if (number === _0n$5) throw new Error("invert: expected non-zero number");
	if (modulo <= _0n$5) throw new Error("invert: expected positive modulus, got " + modulo);
	let a = mod(number, modulo);
	let b = modulo;
	let x = _0n$5, y = _1n$5, u = _1n$5, v = _0n$5;
	while (a !== _0n$5) {
		const q = b / a;
		const r = b % a;
		const m = x - u * q;
		const n = y - v * q;
		b = a, a = r, x = u, y = v, u = m, v = n;
	}
	if (b !== _1n$5) throw new Error("invert: does not exist");
	return mod(x, modulo);
}
function assertIsSquare(Fp, root, n) {
	if (!Fp.eql(Fp.sqr(root), n)) throw new Error("Cannot find square root");
}
function sqrt3mod4(Fp, n) {
	const p1div4 = (Fp.ORDER + _1n$5) / _4n$1;
	const root = Fp.pow(n, p1div4);
	assertIsSquare(Fp, root, n);
	return root;
}
function sqrt5mod8(Fp, n) {
	const p5div8 = (Fp.ORDER - _5n) / _8n;
	const n2 = Fp.mul(n, _2n$4);
	const v = Fp.pow(n2, p5div8);
	const nv = Fp.mul(n, v);
	const i = Fp.mul(Fp.mul(nv, _2n$4), v);
	const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
	assertIsSquare(Fp, root, n);
	return root;
}
function sqrt9mod16(P) {
	const Fp_ = Field(P);
	const tn = tonelliShanks(P);
	const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
	const c2 = tn(Fp_, c1);
	const c3 = tn(Fp_, Fp_.neg(c1));
	const c4 = (P + _7n) / _16n;
	return (Fp, n) => {
		let tv1 = Fp.pow(n, c4);
		let tv2 = Fp.mul(tv1, c1);
		const tv3 = Fp.mul(tv1, c2);
		const tv4 = Fp.mul(tv1, c3);
		const e1 = Fp.eql(Fp.sqr(tv2), n);
		const e2 = Fp.eql(Fp.sqr(tv3), n);
		tv1 = Fp.cmov(tv1, tv2, e1);
		tv2 = Fp.cmov(tv4, tv3, e2);
		const e3 = Fp.eql(Fp.sqr(tv2), n);
		const root = Fp.cmov(tv1, tv2, e3);
		assertIsSquare(Fp, root, n);
		return root;
	};
}
/**
* Tonelli-Shanks square root search algorithm.
* 1. https://eprint.iacr.org/2012/685.pdf (page 12)
* 2. Square Roots from 1; 24, 51, 10 to Dan Shanks
* @param P field order
* @returns function that takes field Fp (created from P) and number n
*/
function tonelliShanks(P) {
	if (P < _3n$4) throw new Error("sqrt is not defined for small field");
	let Q = P - _1n$5;
	let S = 0;
	while (Q % _2n$4 === _0n$5) {
		Q /= _2n$4;
		S++;
	}
	let Z = _2n$4;
	const _Fp = Field(P);
	while (FpLegendre(_Fp, Z) === 1) if (Z++ > 1e3) throw new Error("Cannot find square root: probably non-prime P");
	if (S === 1) return sqrt3mod4;
	let cc = _Fp.pow(Z, Q);
	const Q1div2 = (Q + _1n$5) / _2n$4;
	return function tonelliSlow(Fp, n) {
		if (Fp.is0(n)) return n;
		if (FpLegendre(Fp, n) !== 1) throw new Error("Cannot find square root");
		let M = S;
		let c = Fp.mul(Fp.ONE, cc);
		let t = Fp.pow(n, Q);
		let R = Fp.pow(n, Q1div2);
		while (!Fp.eql(t, Fp.ONE)) {
			if (Fp.is0(t)) return Fp.ZERO;
			let i = 1;
			let t_tmp = Fp.sqr(t);
			while (!Fp.eql(t_tmp, Fp.ONE)) {
				i++;
				t_tmp = Fp.sqr(t_tmp);
				if (i === M) throw new Error("Cannot find square root");
			}
			const exponent = _1n$5 << BigInt(M - i - 1);
			const b = Fp.pow(c, exponent);
			M = i;
			c = Fp.sqr(b);
			t = Fp.mul(t, c);
			R = Fp.mul(R, b);
		}
		return R;
	};
}
/**
* Square root for a finite field. Will try optimized versions first:
*
* 1. P ≡ 3 (mod 4)
* 2. P ≡ 5 (mod 8)
* 3. P ≡ 9 (mod 16)
* 4. Tonelli-Shanks algorithm
*
* Different algorithms can give different roots, it is up to user to decide which one they want.
* For example there is FpSqrtOdd/FpSqrtEven to choice root based on oddness (used for hash-to-curve).
*/
function FpSqrt(P) {
	if (P % _4n$1 === _3n$4) return sqrt3mod4;
	if (P % _8n === _5n) return sqrt5mod8;
	if (P % _16n === _9n) return sqrt9mod16(P);
	return tonelliShanks(P);
}
var FIELD_FIELDS = [
	"create",
	"isValid",
	"is0",
	"neg",
	"inv",
	"sqrt",
	"sqr",
	"eql",
	"add",
	"sub",
	"mul",
	"pow",
	"div",
	"addN",
	"subN",
	"mulN",
	"sqrN"
];
function validateField(field) {
	validateObject(field, FIELD_FIELDS.reduce((map, val) => {
		map[val] = "function";
		return map;
	}, {
		ORDER: "bigint",
		BYTES: "number",
		BITS: "number"
	}));
	return field;
}
/**
* Same as `pow` but for Fp: non-constant-time.
* Unsafe in some contexts: uses ladder, so can expose bigint bits.
*/
function FpPow(Fp, num, power) {
	if (power < _0n$5) throw new Error("invalid exponent, negatives unsupported");
	if (power === _0n$5) return Fp.ONE;
	if (power === _1n$5) return num;
	let p = Fp.ONE;
	let d = num;
	while (power > _0n$5) {
		if (power & _1n$5) p = Fp.mul(p, d);
		d = Fp.sqr(d);
		power >>= _1n$5;
	}
	return p;
}
/**
* Efficiently invert an array of Field elements.
* Exception-free. Will return `undefined` for 0 elements.
* @param passZero map 0 to 0 (instead of undefined)
*/
function FpInvertBatch(Fp, nums, passZero = false) {
	const inverted = new Array(nums.length).fill(passZero ? Fp.ZERO : void 0);
	const multipliedAcc = nums.reduce((acc, num, i) => {
		if (Fp.is0(num)) return acc;
		inverted[i] = acc;
		return Fp.mul(acc, num);
	}, Fp.ONE);
	const invertedAcc = Fp.inv(multipliedAcc);
	nums.reduceRight((acc, num, i) => {
		if (Fp.is0(num)) return acc;
		inverted[i] = Fp.mul(acc, inverted[i]);
		return Fp.mul(acc, num);
	}, invertedAcc);
	return inverted;
}
/**
* Legendre symbol.
* Legendre constant is used to calculate Legendre symbol (a | p)
* which denotes the value of a^((p-1)/2) (mod p).
*
* * (a | p) ≡ 1    if a is a square (mod p), quadratic residue
* * (a | p) ≡ -1   if a is not a square (mod p), quadratic non residue
* * (a | p) ≡ 0    if a ≡ 0 (mod p)
*/
function FpLegendre(Fp, n) {
	const p1mod2 = (Fp.ORDER - _1n$5) / _2n$4;
	const powered = Fp.pow(n, p1mod2);
	const yes = Fp.eql(powered, Fp.ONE);
	const zero = Fp.eql(powered, Fp.ZERO);
	const no = Fp.eql(powered, Fp.neg(Fp.ONE));
	if (!yes && !zero && !no) throw new Error("invalid Legendre symbol result");
	return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
	if (nBitLength !== void 0) anumber(nBitLength);
	const _nBitLength = nBitLength !== void 0 ? nBitLength : n.toString(2).length;
	return {
		nBitLength: _nBitLength,
		nByteLength: Math.ceil(_nBitLength / 8)
	};
}
var _Field = class {
	ORDER;
	BITS;
	BYTES;
	isLE;
	ZERO = _0n$5;
	ONE = _1n$5;
	_lengths;
	_sqrt;
	_mod;
	constructor(ORDER, opts = {}) {
		if (ORDER <= _0n$5) throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
		let _nbitLength = void 0;
		this.isLE = false;
		if (opts != null && typeof opts === "object") {
			if (typeof opts.BITS === "number") _nbitLength = opts.BITS;
			if (typeof opts.sqrt === "function") this.sqrt = opts.sqrt;
			if (typeof opts.isLE === "boolean") this.isLE = opts.isLE;
			if (opts.allowedLengths) this._lengths = opts.allowedLengths?.slice();
			if (typeof opts.modFromBytes === "boolean") this._mod = opts.modFromBytes;
		}
		const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
		if (nByteLength > 2048) throw new Error("invalid field: expected ORDER of <= 2048 bytes");
		this.ORDER = ORDER;
		this.BITS = nBitLength;
		this.BYTES = nByteLength;
		this._sqrt = void 0;
		Object.preventExtensions(this);
	}
	create(num) {
		return mod(num, this.ORDER);
	}
	isValid(num) {
		if (typeof num !== "bigint") throw new Error("invalid field element: expected bigint, got " + typeof num);
		return _0n$5 <= num && num < this.ORDER;
	}
	is0(num) {
		return num === _0n$5;
	}
	isValidNot0(num) {
		return !this.is0(num) && this.isValid(num);
	}
	isOdd(num) {
		return (num & _1n$5) === _1n$5;
	}
	neg(num) {
		return mod(-num, this.ORDER);
	}
	eql(lhs, rhs) {
		return lhs === rhs;
	}
	sqr(num) {
		return mod(num * num, this.ORDER);
	}
	add(lhs, rhs) {
		return mod(lhs + rhs, this.ORDER);
	}
	sub(lhs, rhs) {
		return mod(lhs - rhs, this.ORDER);
	}
	mul(lhs, rhs) {
		return mod(lhs * rhs, this.ORDER);
	}
	pow(num, power) {
		return FpPow(this, num, power);
	}
	div(lhs, rhs) {
		return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
	}
	sqrN(num) {
		return num * num;
	}
	addN(lhs, rhs) {
		return lhs + rhs;
	}
	subN(lhs, rhs) {
		return lhs - rhs;
	}
	mulN(lhs, rhs) {
		return lhs * rhs;
	}
	inv(num) {
		return invert(num, this.ORDER);
	}
	sqrt(num) {
		if (!this._sqrt) this._sqrt = FpSqrt(this.ORDER);
		return this._sqrt(this, num);
	}
	toBytes(num) {
		return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
	}
	fromBytes(bytes, skipValidation = false) {
		abytes(bytes);
		const { _lengths: allowedLengths, BYTES, isLE, ORDER, _mod: modFromBytes } = this;
		if (allowedLengths) {
			if (!allowedLengths.includes(bytes.length) || bytes.length > BYTES) throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
			const padded = new Uint8Array(BYTES);
			padded.set(bytes, isLE ? 0 : padded.length - bytes.length);
			bytes = padded;
		}
		if (bytes.length !== BYTES) throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
		let scalar = isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
		if (modFromBytes) scalar = mod(scalar, ORDER);
		if (!skipValidation) {
			if (!this.isValid(scalar)) throw new Error("invalid field element: outside of range 0..ORDER");
		}
		return scalar;
	}
	invertBatch(lst) {
		return FpInvertBatch(this, lst);
	}
	cmov(a, b, condition) {
		return condition ? b : a;
	}
};
/**
* Creates a finite field. Major performance optimizations:
* * 1. Denormalized operations like mulN instead of mul.
* * 2. Identical object shape: never add or remove keys.
* * 3. `Object.freeze`.
* Fragile: always run a benchmark on a change.
* Security note: operations don't check 'isValid' for all elements for performance reasons,
* it is caller responsibility to check this.
* This is low-level code, please make sure you know what you're doing.
*
* Note about field properties:
* * CHARACTERISTIC p = prime number, number of elements in main subgroup.
* * ORDER q = similar to cofactor in curves, may be composite `q = p^m`.
*
* @param ORDER field order, probably prime, or could be composite
* @param bitLen how many bits the field consumes
* @param isLE (default: false) if encoding / decoding should be in little-endian
* @param redef optional faster redefinitions of sqrt and other methods
*/
function Field(ORDER, opts = {}) {
	return new _Field(ORDER, opts);
}
/**
* Returns total number of bytes consumed by the field element.
* For example, 32 bytes for usual 256-bit weierstrass curve.
* @param fieldOrder number of field elements, usually CURVE.n
* @returns byte length of field
*/
function getFieldBytesLength(fieldOrder) {
	if (typeof fieldOrder !== "bigint") throw new Error("field order must be bigint");
	const bitLength = fieldOrder.toString(2).length;
	return Math.ceil(bitLength / 8);
}
/**
* Returns minimal amount of bytes that can be safely reduced
* by field order.
* Should be 2^-128 for 128-bit curve such as P256.
* @param fieldOrder number of field elements, usually CURVE.n
* @returns byte length of target hash
*/
function getMinHashLength(fieldOrder) {
	const length = getFieldBytesLength(fieldOrder);
	return length + Math.ceil(length / 2);
}
/**
* "Constant-time" private key generation utility.
* Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
* and convert them into private scalar, with the modulo bias being negligible.
* Needs at least 48 bytes of input for 32-byte private key.
* https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
* FIPS 186-5, A.2 https://csrc.nist.gov/publications/detail/fips/186/5/final
* RFC 9380, https://www.rfc-editor.org/rfc/rfc9380#section-5
* @param hash hash output from SHA3 or a similar function
* @param groupOrder size of subgroup - (e.g. secp256k1.Point.Fn.ORDER)
* @param isLE interpret hash bytes as LE num
* @returns valid private scalar
*/
function mapHashToField(key, fieldOrder, isLE = false) {
	abytes(key);
	const len = key.length;
	const fieldLen = getFieldBytesLength(fieldOrder);
	const minLen = getMinHashLength(fieldOrder);
	if (len < 16 || len < minLen || len > 1024) throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
	const reduced = mod(isLE ? bytesToNumberLE(key) : bytesToNumberBE(key), fieldOrder - _1n$5) + _1n$5;
	return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}
//#endregion
//#region node_modules/@noble/curves/abstract/curve.js
/**
* Methods for elliptic curve multiplication by scalars.
* Contains wNAF, pippenger.
* @module
*/
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n$4 = /* @__PURE__ */ BigInt(0);
var _1n$4 = /* @__PURE__ */ BigInt(1);
function negateCt(condition, item) {
	const neg = item.negate();
	return condition ? neg : item;
}
/**
* Takes a bunch of Projective Points but executes only one
* inversion on all of them. Inversion is very slow operation,
* so this improves performance massively.
* Optimization: converts a list of projective points to a list of identical points with Z=1.
*/
function normalizeZ(c, points) {
	const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
	return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W, bits) {
	if (!Number.isSafeInteger(W) || W <= 0 || W > bits) throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
	validateW(W, scalarBits);
	const windows = Math.ceil(scalarBits / W) + 1;
	const windowSize = 2 ** (W - 1);
	const maxNumber = 2 ** W;
	return {
		windows,
		windowSize,
		mask: bitMask(W),
		maxNumber,
		shiftBy: BigInt(W)
	};
}
function calcOffsets(n, window, wOpts) {
	const { windowSize, mask, maxNumber, shiftBy } = wOpts;
	let wbits = Number(n & mask);
	let nextN = n >> shiftBy;
	if (wbits > windowSize) {
		wbits -= maxNumber;
		nextN += _1n$4;
	}
	const offsetStart = window * windowSize;
	const offset = offsetStart + Math.abs(wbits) - 1;
	const isZero = wbits === 0;
	const isNeg = wbits < 0;
	const isNegF = window % 2 !== 0;
	return {
		nextN,
		offset,
		isZero,
		isNeg,
		isNegF,
		offsetF: offsetStart
	};
}
var pointPrecomputes = /* @__PURE__ */ new WeakMap();
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getW(P) {
	return pointWindowSizes.get(P) || 1;
}
function assert0(n) {
	if (n !== _0n$4) throw new Error("invalid wNAF");
}
/**
* Elliptic curve multiplication of Point by scalar. Fragile.
* Table generation takes **30MB of ram and 10ms on high-end CPU**,
* but may take much longer on slow devices. Actual generation will happen on
* first call of `multiply()`. By default, `BASE` point is precomputed.
*
* Scalars should always be less than curve order: this should be checked inside of a curve itself.
* Creates precomputation tables for fast multiplication:
* - private scalar is split by fixed size windows of W bits
* - every window point is collected from window's table & added to accumulator
* - since windows are different, same point inside tables won't be accessed more than once per calc
* - each multiplication is 'Math.ceil(CURVE_ORDER / 𝑊) + 1' point additions (fixed for any scalar)
* - +1 window is neccessary for wNAF
* - wNAF reduces table size: 2x less memory + 2x faster generation, but 10% slower multiplication
*
* @todo Research returning 2d JS array of windows, instead of a single window.
* This would allow windows to be in different memory locations
*/
var wNAF = class {
	BASE;
	ZERO;
	Fn;
	bits;
	constructor(Point, bits) {
		this.BASE = Point.BASE;
		this.ZERO = Point.ZERO;
		this.Fn = Point.Fn;
		this.bits = bits;
	}
	_unsafeLadder(elm, n, p = this.ZERO) {
		let d = elm;
		while (n > _0n$4) {
			if (n & _1n$4) p = p.add(d);
			d = d.double();
			n >>= _1n$4;
		}
		return p;
	}
	/**
	* Creates a wNAF precomputation window. Used for caching.
	* Default window size is set by `utils.precompute()` and is equal to 8.
	* Number of precomputed points depends on the curve size:
	* 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
	* - 𝑊 is the window size
	* - 𝑛 is the bitlength of the curve order.
	* For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
	* @param point Point instance
	* @param W window size
	* @returns precomputed point tables flattened to a single array
	*/
	precomputeWindow(point, W) {
		const { windows, windowSize } = calcWOpts(W, this.bits);
		const points = [];
		let p = point;
		let base = p;
		for (let window = 0; window < windows; window++) {
			base = p;
			points.push(base);
			for (let i = 1; i < windowSize; i++) {
				base = base.add(p);
				points.push(base);
			}
			p = base.double();
		}
		return points;
	}
	/**
	* Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
	* More compact implementation:
	* https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
	* @returns real and fake (for const-time) points
	*/
	wNAF(W, precomputes, n) {
		if (!this.Fn.isValid(n)) throw new Error("invalid scalar");
		let p = this.ZERO;
		let f = this.BASE;
		const wo = calcWOpts(W, this.bits);
		for (let window = 0; window < wo.windows; window++) {
			const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
			n = nextN;
			if (isZero) f = f.add(negateCt(isNegF, precomputes[offsetF]));
			else p = p.add(negateCt(isNeg, precomputes[offset]));
		}
		assert0(n);
		return {
			p,
			f
		};
	}
	/**
	* Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
	* @param acc accumulator point to add result of multiplication
	* @returns point
	*/
	wNAFUnsafe(W, precomputes, n, acc = this.ZERO) {
		const wo = calcWOpts(W, this.bits);
		for (let window = 0; window < wo.windows; window++) {
			if (n === _0n$4) break;
			const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
			n = nextN;
			if (isZero) continue;
			else {
				const item = precomputes[offset];
				acc = acc.add(isNeg ? item.negate() : item);
			}
		}
		assert0(n);
		return acc;
	}
	getPrecomputes(W, point, transform) {
		let comp = pointPrecomputes.get(point);
		if (!comp) {
			comp = this.precomputeWindow(point, W);
			if (W !== 1) {
				if (typeof transform === "function") comp = transform(comp);
				pointPrecomputes.set(point, comp);
			}
		}
		return comp;
	}
	cached(point, scalar, transform) {
		const W = getW(point);
		return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
	}
	unsafe(point, scalar, transform, prev) {
		const W = getW(point);
		if (W === 1) return this._unsafeLadder(point, scalar, prev);
		return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
	}
	createCache(P, W) {
		validateW(W, this.bits);
		pointWindowSizes.set(P, W);
		pointPrecomputes.delete(P);
	}
	hasCache(elm) {
		return getW(elm) !== 1;
	}
};
/**
* Endomorphism-specific multiplication for Koblitz curves.
* Cost: 128 dbl, 0-256 adds.
*/
function mulEndoUnsafe(Point, point, k1, k2) {
	let acc = point;
	let p1 = Point.ZERO;
	let p2 = Point.ZERO;
	while (k1 > _0n$4 || k2 > _0n$4) {
		if (k1 & _1n$4) p1 = p1.add(acc);
		if (k2 & _1n$4) p2 = p2.add(acc);
		acc = acc.double();
		k1 >>= _1n$4;
		k2 >>= _1n$4;
	}
	return {
		p1,
		p2
	};
}
function createField(order, field, isLE) {
	if (field) {
		if (field.ORDER !== order) throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
		validateField(field);
		return field;
	} else return Field(order, { isLE });
}
/** Validates CURVE opts and creates fields */
function createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
	if (FpFnLE === void 0) FpFnLE = type === "edwards";
	if (!CURVE || typeof CURVE !== "object") throw new Error(`expected valid ${type} CURVE object`);
	for (const p of [
		"p",
		"n",
		"h"
	]) {
		const val = CURVE[p];
		if (!(typeof val === "bigint" && val > _0n$4)) throw new Error(`CURVE.${p} must be positive bigint`);
	}
	const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
	const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
	const params = [
		"Gx",
		"Gy",
		"a",
		type === "weierstrass" ? "b" : "d"
	];
	for (const p of params) if (!Fp.isValid(CURVE[p])) throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
	CURVE = Object.freeze(Object.assign({}, CURVE));
	return {
		CURVE,
		Fp,
		Fn
	};
}
//#endregion
//#region node_modules/@noble/curves/abstract/weierstrass.js
var divNearest = (num, den) => (num + (num >= 0 ? den : -den) / _2n$3) / den;
/**
* Splits scalar for GLV endomorphism.
*/
function _splitEndoScalar(k, basis, n) {
	const [[a1, b1], [a2, b2]] = basis;
	const c1 = divNearest(b2 * k, n);
	const c2 = divNearest(-b1 * k, n);
	let k1 = k - c1 * a1 - c2 * a2;
	let k2 = -c1 * b1 - c2 * b2;
	const k1neg = k1 < _0n$3;
	const k2neg = k2 < _0n$3;
	if (k1neg) k1 = -k1;
	if (k2neg) k2 = -k2;
	const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n$3;
	if (k1 < _0n$3 || k1 >= MAX_NUM || k2 < _0n$3 || k2 >= MAX_NUM) throw new Error("splitScalar (endomorphism): failed, k=" + k);
	return {
		k1neg,
		k1,
		k2neg,
		k2
	};
}
var _0n$3 = BigInt(0), _1n$3 = BigInt(1), _2n$3 = BigInt(2), _3n$3 = BigInt(3), _4n = BigInt(4);
/**
* Creates weierstrass Point constructor, based on specified curve options.
*
* See {@link WeierstrassOpts}.
*
* @example
```js
const opts = {
p: 0xfffffffffffffffffffffffffffffffeffffac73n,
n: 0x100000000000000000001b8fa16dfab9aca16b6b3n,
h: 1n,
a: 0n,
b: 7n,
Gx: 0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebbn,
Gy: 0x938cf935318fdced6bc28286531733c3f03c4feen,
};
const secp160k1_Point = weierstrass(opts);
```
*/
function weierstrass(params, extraOpts = {}) {
	const validated = createCurveFields("weierstrass", params, extraOpts);
	const { Fp, Fn } = validated;
	let CURVE = validated.CURVE;
	const { h: cofactor, n: CURVE_ORDER } = CURVE;
	validateObject(extraOpts, {}, {
		allowInfinityPoint: "boolean",
		clearCofactor: "function",
		isTorsionFree: "function",
		fromBytes: "function",
		toBytes: "function",
		endo: "object"
	});
	const { endo } = extraOpts;
	if (endo) {
		if (!Fp.is0(CURVE.a) || typeof endo.beta !== "bigint" || !Array.isArray(endo.basises)) throw new Error("invalid endo: expected \"beta\": bigint and \"basises\": array");
	}
	const lengths = getWLengths(Fp, Fn);
	function assertCompressionIsSupported() {
		if (!Fp.isOdd) throw new Error("compression is not supported: Field does not have .isOdd()");
	}
	function pointToBytes(_c, point, isCompressed) {
		const { x, y } = point.toAffine();
		const bx = Fp.toBytes(x);
		abool(isCompressed, "isCompressed");
		if (isCompressed) {
			assertCompressionIsSupported();
			return concatBytes(pprefix(!Fp.isOdd(y)), bx);
		} else return concatBytes(Uint8Array.of(4), bx, Fp.toBytes(y));
	}
	function pointFromBytes(bytes) {
		abytes(bytes, void 0, "Point");
		const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
		const length = bytes.length;
		const head = bytes[0];
		const tail = bytes.subarray(1);
		if (length === comp && (head === 2 || head === 3)) {
			const x = Fp.fromBytes(tail);
			if (!Fp.isValid(x)) throw new Error("bad point: is not on curve, wrong x");
			const y2 = weierstrassEquation(x);
			let y;
			try {
				y = Fp.sqrt(y2);
			} catch (sqrtError) {
				const err = sqrtError instanceof Error ? ": " + sqrtError.message : "";
				throw new Error("bad point: is not on curve, sqrt error" + err);
			}
			assertCompressionIsSupported();
			const evenY = Fp.isOdd(y);
			if ((head & 1) === 1 !== evenY) y = Fp.neg(y);
			return {
				x,
				y
			};
		} else if (length === uncomp && head === 4) {
			const L = Fp.BYTES;
			const x = Fp.fromBytes(tail.subarray(0, L));
			const y = Fp.fromBytes(tail.subarray(L, L * 2));
			if (!isValidXY(x, y)) throw new Error("bad point: is not on curve");
			return {
				x,
				y
			};
		} else throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
	}
	const encodePoint = extraOpts.toBytes || pointToBytes;
	const decodePoint = extraOpts.fromBytes || pointFromBytes;
	function weierstrassEquation(x) {
		const x2 = Fp.sqr(x);
		const x3 = Fp.mul(x2, x);
		return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b);
	}
	/** Checks whether equation holds for given x, y: y² == x³ + ax + b */
	function isValidXY(x, y) {
		const left = Fp.sqr(y);
		const right = weierstrassEquation(x);
		return Fp.eql(left, right);
	}
	if (!isValidXY(CURVE.Gx, CURVE.Gy)) throw new Error("bad curve params: generator point");
	const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n$3), _4n);
	const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
	if (Fp.is0(Fp.add(_4a3, _27b2))) throw new Error("bad curve params: a or b");
	/** Asserts coordinate is valid: 0 <= n < Fp.ORDER. */
	function acoord(title, n, banZero = false) {
		if (!Fp.isValid(n) || banZero && Fp.is0(n)) throw new Error(`bad point coordinate ${title}`);
		return n;
	}
	function aprjpoint(other) {
		if (!(other instanceof Point)) throw new Error("Weierstrass Point expected");
	}
	function splitEndoScalarN(k) {
		if (!endo || !endo.basises) throw new Error("no endo");
		return _splitEndoScalar(k, endo.basises, Fn.ORDER);
	}
	const toAffineMemo = memoized((p, iz) => {
		const { X, Y, Z } = p;
		if (Fp.eql(Z, Fp.ONE)) return {
			x: X,
			y: Y
		};
		const is0 = p.is0();
		if (iz == null) iz = is0 ? Fp.ONE : Fp.inv(Z);
		const x = Fp.mul(X, iz);
		const y = Fp.mul(Y, iz);
		const zz = Fp.mul(Z, iz);
		if (is0) return {
			x: Fp.ZERO,
			y: Fp.ZERO
		};
		if (!Fp.eql(zz, Fp.ONE)) throw new Error("invZ was invalid");
		return {
			x,
			y
		};
	});
	const assertValidMemo = memoized((p) => {
		if (p.is0()) {
			if (extraOpts.allowInfinityPoint && !Fp.is0(p.Y)) return;
			throw new Error("bad point: ZERO");
		}
		const { x, y } = p.toAffine();
		if (!Fp.isValid(x) || !Fp.isValid(y)) throw new Error("bad point: x or y not field elements");
		if (!isValidXY(x, y)) throw new Error("bad point: equation left != right");
		if (!p.isTorsionFree()) throw new Error("bad point: not in prime-order subgroup");
		return true;
	});
	function finishEndo(endoBeta, k1p, k2p, k1neg, k2neg) {
		k2p = new Point(Fp.mul(k2p.X, endoBeta), k2p.Y, k2p.Z);
		k1p = negateCt(k1neg, k1p);
		k2p = negateCt(k2neg, k2p);
		return k1p.add(k2p);
	}
	/**
	* Projective Point works in 3d / projective (homogeneous) coordinates:(X, Y, Z) ∋ (x=X/Z, y=Y/Z).
	* Default Point works in 2d / affine coordinates: (x, y).
	* We're doing calculations in projective, because its operations don't require costly inversion.
	*/
	class Point {
		static BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
		static ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
		static Fp = Fp;
		static Fn = Fn;
		X;
		Y;
		Z;
		/** Does NOT validate if the point is valid. Use `.assertValidity()`. */
		constructor(X, Y, Z) {
			this.X = acoord("x", X);
			this.Y = acoord("y", Y, true);
			this.Z = acoord("z", Z);
			Object.freeze(this);
		}
		static CURVE() {
			return CURVE;
		}
		/** Does NOT validate if the point is valid. Use `.assertValidity()`. */
		static fromAffine(p) {
			const { x, y } = p || {};
			if (!p || !Fp.isValid(x) || !Fp.isValid(y)) throw new Error("invalid affine point");
			if (p instanceof Point) throw new Error("projective point not allowed");
			if (Fp.is0(x) && Fp.is0(y)) return Point.ZERO;
			return new Point(x, y, Fp.ONE);
		}
		static fromBytes(bytes) {
			const P = Point.fromAffine(decodePoint(abytes(bytes, void 0, "point")));
			P.assertValidity();
			return P;
		}
		static fromHex(hex) {
			return Point.fromBytes(hexToBytes(hex));
		}
		get x() {
			return this.toAffine().x;
		}
		get y() {
			return this.toAffine().y;
		}
		/**
		*
		* @param windowSize
		* @param isLazy true will defer table computation until the first multiplication
		* @returns
		*/
		precompute(windowSize = 8, isLazy = true) {
			wnaf.createCache(this, windowSize);
			if (!isLazy) this.multiply(_3n$3);
			return this;
		}
		/** A point on curve is valid if it conforms to equation. */
		assertValidity() {
			assertValidMemo(this);
		}
		hasEvenY() {
			const { y } = this.toAffine();
			if (!Fp.isOdd) throw new Error("Field doesn't support isOdd");
			return !Fp.isOdd(y);
		}
		/** Compare one point to another. */
		equals(other) {
			aprjpoint(other);
			const { X: X1, Y: Y1, Z: Z1 } = this;
			const { X: X2, Y: Y2, Z: Z2 } = other;
			const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
			const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
			return U1 && U2;
		}
		/** Flips point to one corresponding to (x, -y) in Affine coordinates. */
		negate() {
			return new Point(this.X, Fp.neg(this.Y), this.Z);
		}
		double() {
			const { a, b } = CURVE;
			const b3 = Fp.mul(b, _3n$3);
			const { X: X1, Y: Y1, Z: Z1 } = this;
			let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
			let t0 = Fp.mul(X1, X1);
			let t1 = Fp.mul(Y1, Y1);
			let t2 = Fp.mul(Z1, Z1);
			let t3 = Fp.mul(X1, Y1);
			t3 = Fp.add(t3, t3);
			Z3 = Fp.mul(X1, Z1);
			Z3 = Fp.add(Z3, Z3);
			X3 = Fp.mul(a, Z3);
			Y3 = Fp.mul(b3, t2);
			Y3 = Fp.add(X3, Y3);
			X3 = Fp.sub(t1, Y3);
			Y3 = Fp.add(t1, Y3);
			Y3 = Fp.mul(X3, Y3);
			X3 = Fp.mul(t3, X3);
			Z3 = Fp.mul(b3, Z3);
			t2 = Fp.mul(a, t2);
			t3 = Fp.sub(t0, t2);
			t3 = Fp.mul(a, t3);
			t3 = Fp.add(t3, Z3);
			Z3 = Fp.add(t0, t0);
			t0 = Fp.add(Z3, t0);
			t0 = Fp.add(t0, t2);
			t0 = Fp.mul(t0, t3);
			Y3 = Fp.add(Y3, t0);
			t2 = Fp.mul(Y1, Z1);
			t2 = Fp.add(t2, t2);
			t0 = Fp.mul(t2, t3);
			X3 = Fp.sub(X3, t0);
			Z3 = Fp.mul(t2, t1);
			Z3 = Fp.add(Z3, Z3);
			Z3 = Fp.add(Z3, Z3);
			return new Point(X3, Y3, Z3);
		}
		add(other) {
			aprjpoint(other);
			const { X: X1, Y: Y1, Z: Z1 } = this;
			const { X: X2, Y: Y2, Z: Z2 } = other;
			let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
			const a = CURVE.a;
			const b3 = Fp.mul(CURVE.b, _3n$3);
			let t0 = Fp.mul(X1, X2);
			let t1 = Fp.mul(Y1, Y2);
			let t2 = Fp.mul(Z1, Z2);
			let t3 = Fp.add(X1, Y1);
			let t4 = Fp.add(X2, Y2);
			t3 = Fp.mul(t3, t4);
			t4 = Fp.add(t0, t1);
			t3 = Fp.sub(t3, t4);
			t4 = Fp.add(X1, Z1);
			let t5 = Fp.add(X2, Z2);
			t4 = Fp.mul(t4, t5);
			t5 = Fp.add(t0, t2);
			t4 = Fp.sub(t4, t5);
			t5 = Fp.add(Y1, Z1);
			X3 = Fp.add(Y2, Z2);
			t5 = Fp.mul(t5, X3);
			X3 = Fp.add(t1, t2);
			t5 = Fp.sub(t5, X3);
			Z3 = Fp.mul(a, t4);
			X3 = Fp.mul(b3, t2);
			Z3 = Fp.add(X3, Z3);
			X3 = Fp.sub(t1, Z3);
			Z3 = Fp.add(t1, Z3);
			Y3 = Fp.mul(X3, Z3);
			t1 = Fp.add(t0, t0);
			t1 = Fp.add(t1, t0);
			t2 = Fp.mul(a, t2);
			t4 = Fp.mul(b3, t4);
			t1 = Fp.add(t1, t2);
			t2 = Fp.sub(t0, t2);
			t2 = Fp.mul(a, t2);
			t4 = Fp.add(t4, t2);
			t0 = Fp.mul(t1, t4);
			Y3 = Fp.add(Y3, t0);
			t0 = Fp.mul(t5, t4);
			X3 = Fp.mul(t3, X3);
			X3 = Fp.sub(X3, t0);
			t0 = Fp.mul(t3, t1);
			Z3 = Fp.mul(t5, Z3);
			Z3 = Fp.add(Z3, t0);
			return new Point(X3, Y3, Z3);
		}
		subtract(other) {
			return this.add(other.negate());
		}
		is0() {
			return this.equals(Point.ZERO);
		}
		/**
		* Constant time multiplication.
		* Uses wNAF method. Windowed method may be 10% faster,
		* but takes 2x longer to generate and consumes 2x memory.
		* Uses precomputes when available.
		* Uses endomorphism for Koblitz curves.
		* @param scalar by which the point would be multiplied
		* @returns New point
		*/
		multiply(scalar) {
			const { endo } = extraOpts;
			if (!Fn.isValidNot0(scalar)) throw new Error("invalid scalar: out of range");
			let point, fake;
			const mul = (n) => wnaf.cached(this, n, (p) => normalizeZ(Point, p));
			/** See docs for {@link EndomorphismOpts} */
			if (endo) {
				const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(scalar);
				const { p: k1p, f: k1f } = mul(k1);
				const { p: k2p, f: k2f } = mul(k2);
				fake = k1f.add(k2f);
				point = finishEndo(endo.beta, k1p, k2p, k1neg, k2neg);
			} else {
				const { p, f } = mul(scalar);
				point = p;
				fake = f;
			}
			return normalizeZ(Point, [point, fake])[0];
		}
		/**
		* Non-constant-time multiplication. Uses double-and-add algorithm.
		* It's faster, but should only be used when you don't care about
		* an exposed secret key e.g. sig verification, which works over *public* keys.
		*/
		multiplyUnsafe(sc) {
			const { endo } = extraOpts;
			const p = this;
			if (!Fn.isValid(sc)) throw new Error("invalid scalar: out of range");
			if (sc === _0n$3 || p.is0()) return Point.ZERO;
			if (sc === _1n$3) return p;
			if (wnaf.hasCache(this)) return this.multiply(sc);
			if (endo) {
				const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(sc);
				const { p1, p2 } = mulEndoUnsafe(Point, p, k1, k2);
				return finishEndo(endo.beta, p1, p2, k1neg, k2neg);
			} else return wnaf.unsafe(p, sc);
		}
		/**
		* Converts Projective point to affine (x, y) coordinates.
		* @param invertedZ Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
		*/
		toAffine(invertedZ) {
			return toAffineMemo(this, invertedZ);
		}
		/**
		* Checks whether Point is free of torsion elements (is in prime subgroup).
		* Always torsion-free for cofactor=1 curves.
		*/
		isTorsionFree() {
			const { isTorsionFree } = extraOpts;
			if (cofactor === _1n$3) return true;
			if (isTorsionFree) return isTorsionFree(Point, this);
			return wnaf.unsafe(this, CURVE_ORDER).is0();
		}
		clearCofactor() {
			const { clearCofactor } = extraOpts;
			if (cofactor === _1n$3) return this;
			if (clearCofactor) return clearCofactor(Point, this);
			return this.multiplyUnsafe(cofactor);
		}
		isSmallOrder() {
			return this.multiplyUnsafe(cofactor).is0();
		}
		toBytes(isCompressed = true) {
			abool(isCompressed, "isCompressed");
			this.assertValidity();
			return encodePoint(Point, this, isCompressed);
		}
		toHex(isCompressed = true) {
			return bytesToHex(this.toBytes(isCompressed));
		}
		toString() {
			return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
		}
	}
	const bits = Fn.BITS;
	const wnaf = new wNAF(Point, extraOpts.endo ? Math.ceil(bits / 2) : bits);
	Point.BASE.precompute(8);
	return Point;
}
function pprefix(hasEvenY) {
	return Uint8Array.of(hasEvenY ? 2 : 3);
}
function getWLengths(Fp, Fn) {
	return {
		secretKey: Fn.BYTES,
		publicKey: 1 + Fp.BYTES,
		publicKeyUncompressed: 1 + 2 * Fp.BYTES,
		publicKeyHasPrefix: true,
		signature: 2 * Fn.BYTES
	};
}
//#endregion
//#region node_modules/@noble/curves/abstract/bls.js
/**
* BLS != BLS.
* The file implements BLS (Boneh-Lynn-Shacham) signatures.
* Used in both BLS (Barreto-Lynn-Scott) and BN (Barreto-Naehrig)
* families of pairing-friendly curves.
* Consists of two curves: G1 and G2:
* - G1 is a subgroup of (x, y) E(Fq) over y² = x³ + 4.
* - G2 is a subgroup of ((x₁, x₂+i), (y₁, y₂+i)) E(Fq²) over y² = x³ + 4(1 + i) where i is √-1
* - Gt, created by bilinear (ate) pairing e(G1, G2), consists of p-th roots of unity in
*   Fq^k where k is embedding degree. Only degree 12 is currently supported, 24 is not.
* Pairing is used to aggregate and verify signatures.
* There are two modes of operation:
* - Long signatures:  X-byte keys + 2X-byte sigs (G1 keys + G2 sigs).
* - Short signatures: 2X-byte keys + X-byte sigs (G2 keys + G1 sigs).
* @module
**/
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n$2 = BigInt(0), _1n$2 = BigInt(1), _2n$2 = BigInt(2), _3n$2 = BigInt(3);
function NAfDecomposition(a) {
	const res = [];
	for (; a > _1n$2; a >>= _1n$2) if ((a & _1n$2) === _0n$2) res.unshift(0);
	else if ((a & _3n$2) === _3n$2) {
		res.unshift(-1);
		a += _1n$2;
	} else res.unshift(1);
	return res;
}
function createBlsPairing(fields, G1, G2, params) {
	const { Fr, Fp2, Fp12 } = fields;
	const { twistType, ateLoopSize, xNegative, postPrecompute } = params;
	let lineFunction;
	if (twistType === "multiplicative") lineFunction = (c0, c1, c2, f, Px, Py) => Fp12.mul014(f, c0, Fp2.mul(c1, Px), Fp2.mul(c2, Py));
	else if (twistType === "divisive") lineFunction = (c0, c1, c2, f, Px, Py) => Fp12.mul034(f, Fp2.mul(c2, Py), Fp2.mul(c1, Px), c0);
	else throw new Error("bls: unknown twist type");
	const Fp2div2 = Fp2.div(Fp2.ONE, Fp2.mul(Fp2.ONE, _2n$2));
	function pointDouble(ell, Rx, Ry, Rz) {
		const t0 = Fp2.sqr(Ry);
		const t1 = Fp2.sqr(Rz);
		const t2 = Fp2.mulByB(Fp2.mul(t1, _3n$2));
		const t3 = Fp2.mul(t2, _3n$2);
		const t4 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Ry, Rz)), t1), t0);
		const c0 = Fp2.sub(t2, t0);
		const c1 = Fp2.mul(Fp2.sqr(Rx), _3n$2);
		const c2 = Fp2.neg(t4);
		ell.push([
			c0,
			c1,
			c2
		]);
		Rx = Fp2.mul(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), Fp2div2);
		Ry = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), Fp2div2)), Fp2.mul(Fp2.sqr(t2), _3n$2));
		Rz = Fp2.mul(t0, t4);
		return {
			Rx,
			Ry,
			Rz
		};
	}
	function pointAdd(ell, Rx, Ry, Rz, Qx, Qy) {
		const t0 = Fp2.sub(Ry, Fp2.mul(Qy, Rz));
		const t1 = Fp2.sub(Rx, Fp2.mul(Qx, Rz));
		const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy));
		const c1 = Fp2.neg(t0);
		const c2 = t1;
		ell.push([
			c0,
			c1,
			c2
		]);
		const t2 = Fp2.sqr(t1);
		const t3 = Fp2.mul(t2, t1);
		const t4 = Fp2.mul(t2, Rx);
		const t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, _2n$2)), Fp2.mul(Fp2.sqr(t0), Rz));
		Rx = Fp2.mul(t1, t5);
		Ry = Fp2.sub(Fp2.mul(Fp2.sub(t4, t5), t0), Fp2.mul(t3, Ry));
		Rz = Fp2.mul(Rz, t3);
		return {
			Rx,
			Ry,
			Rz
		};
	}
	const ATE_NAF = NAfDecomposition(ateLoopSize);
	const calcPairingPrecomputes = memoized((point) => {
		const { x, y } = point.toAffine();
		const Qx = x, Qy = y, negQy = Fp2.neg(y);
		let Rx = Qx, Ry = Qy, Rz = Fp2.ONE;
		const ell = [];
		for (const bit of ATE_NAF) {
			const cur = [];
			({Rx, Ry, Rz} = pointDouble(cur, Rx, Ry, Rz));
			if (bit) ({Rx, Ry, Rz} = pointAdd(cur, Rx, Ry, Rz, Qx, bit === -1 ? negQy : Qy));
			ell.push(cur);
		}
		if (postPrecompute) {
			const last = ell[ell.length - 1];
			postPrecompute(Rx, Ry, Rz, Qx, Qy, pointAdd.bind(null, last));
		}
		return ell;
	});
	function millerLoopBatch(pairs, withFinalExponent = false) {
		let f12 = Fp12.ONE;
		if (pairs.length) {
			const ellLen = pairs[0][0].length;
			for (let i = 0; i < ellLen; i++) {
				f12 = Fp12.sqr(f12);
				for (const [ell, Px, Py] of pairs) for (const [c0, c1, c2] of ell[i]) f12 = lineFunction(c0, c1, c2, f12, Px, Py);
			}
		}
		if (xNegative) f12 = Fp12.conjugate(f12);
		return withFinalExponent ? Fp12.finalExponentiate(f12) : f12;
	}
	function pairingBatch(pairs, withFinalExponent = true) {
		const res = [];
		normalizeZ(G1, pairs.map(({ g1 }) => g1));
		normalizeZ(G2, pairs.map(({ g2 }) => g2));
		for (const { g1, g2 } of pairs) {
			if (g1.is0() || g2.is0()) throw new Error("pairing is not available for ZERO point");
			g1.assertValidity();
			g2.assertValidity();
			const Qa = g1.toAffine();
			res.push([
				calcPairingPrecomputes(g2),
				Qa.x,
				Qa.y
			]);
		}
		return millerLoopBatch(res, withFinalExponent);
	}
	function pairing(Q, P, withFinalExponent = true) {
		return pairingBatch([{
			g1: Q,
			g2: P
		}], withFinalExponent);
	}
	const lengths = { seed: getMinHashLength(Fr.ORDER) };
	const rand = params.randomBytes || randomBytes;
	const randomSecretKey = (seed = rand(lengths.seed)) => {
		abytes(seed, lengths.seed, "seed");
		return mapHashToField(seed, Fr.ORDER);
	};
	return {
		lengths,
		Fr,
		Fp12,
		millerLoopBatch,
		pairing,
		pairingBatch,
		calcPairingPrecomputes,
		randomSecretKey
	};
}
function blsBasic(fields, G1_Point, G2_Point, params) {
	const { Fp, Fr, Fp2, Fp6, Fp12 } = fields;
	const G1 = { Point: G1_Point };
	const G2 = { Point: G2_Point };
	const { millerLoopBatch, pairing, pairingBatch, calcPairingPrecomputes, randomSecretKey, lengths } = createBlsPairing(fields, G1_Point, G2_Point, params);
	G1.Point.BASE.precompute(4);
	return Object.freeze({
		lengths,
		millerLoopBatch,
		pairing,
		pairingBatch,
		G1,
		G2,
		fields: {
			Fr,
			Fp,
			Fp2,
			Fp6,
			Fp12
		},
		params: {
			ateLoopSize: params.ateLoopSize,
			twistType: params.twistType
		},
		utils: {
			randomSecretKey,
			calcPairingPrecomputes
		}
	});
}
//#endregion
//#region node_modules/@noble/curves/abstract/tower.js
/**
* Towered extension fields.
* Rather than implementing a massive 12th-degree extension directly, it is more efficient
* to build it up from smaller extensions: a tower of extensions.
*
* For BLS12-381, the Fp12 field is implemented as a quadratic (degree two) extension,
* on top of a cubic (degree three) extension, on top of a quadratic extension of Fp.
*
* For more info: "Pairings for beginners" by Costello, section 7.3.
* @module
*/
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n$1 = BigInt(0), _1n$1 = BigInt(1), _2n$1 = BigInt(2), _3n$1 = BigInt(3);
function calcFrobeniusCoefficients(Fp, nonResidue, modulus, degree, num = 1, divisor) {
	const _divisor = BigInt(divisor === void 0 ? degree : divisor);
	const towerModulus = modulus ** BigInt(degree);
	const res = [];
	for (let i = 0; i < num; i++) {
		const a = BigInt(i + 1);
		const powers = [];
		for (let j = 0, qPower = _1n$1; j < degree; j++) {
			const power = (a * qPower - a) / _divisor % towerModulus;
			powers.push(Fp.pow(nonResidue, power));
			qPower *= modulus;
		}
		res.push(powers);
	}
	return res;
}
function psiFrobenius(Fp, Fp2, base) {
	const PSI_X = Fp2.pow(base, (Fp.ORDER - _1n$1) / _3n$1);
	const PSI_Y = Fp2.pow(base, (Fp.ORDER - _1n$1) / _2n$1);
	function psi(x, y) {
		return [Fp2.mul(Fp2.frobeniusMap(x, 1), PSI_X), Fp2.mul(Fp2.frobeniusMap(y, 1), PSI_Y)];
	}
	const PSI2_X = Fp2.pow(base, (Fp.ORDER ** _2n$1 - _1n$1) / _3n$1);
	const PSI2_Y = Fp2.pow(base, (Fp.ORDER ** _2n$1 - _1n$1) / _2n$1);
	if (!Fp2.eql(PSI2_Y, Fp2.neg(Fp2.ONE))) throw new Error("psiFrobenius: PSI2_Y!==-1");
	function psi2(x, y) {
		return [Fp2.mul(x, PSI2_X), Fp2.neg(y)];
	}
	const mapAffine = (fn) => (c, P) => {
		const affine = P.toAffine();
		const p = fn(affine.x, affine.y);
		return c.fromAffine({
			x: p[0],
			y: p[1]
		});
	};
	return {
		psi,
		psi2,
		G2psi: mapAffine(psi),
		G2psi2: mapAffine(psi2),
		PSI_X,
		PSI_Y,
		PSI2_X,
		PSI2_Y
	};
}
var Fp2fromBigTuple = (Fp, tuple) => {
	if (tuple.length !== 2) throw new Error("invalid tuple");
	const fps = tuple.map((n) => Fp.create(n));
	return {
		c0: fps[0],
		c1: fps[1]
	};
};
var _Field2 = class {
	ORDER;
	BITS;
	BYTES;
	isLE;
	ZERO;
	ONE;
	Fp;
	NONRESIDUE;
	mulByB;
	Fp_NONRESIDUE;
	Fp_div2;
	FROBENIUS_COEFFICIENTS;
	constructor(Fp, opts = {}) {
		const ORDER = Fp.ORDER;
		const FP2_ORDER = ORDER * ORDER;
		this.Fp = Fp;
		this.ORDER = FP2_ORDER;
		this.BITS = bitLen(FP2_ORDER);
		this.BYTES = Math.ceil(bitLen(FP2_ORDER) / 8);
		this.isLE = Fp.isLE;
		this.ZERO = {
			c0: Fp.ZERO,
			c1: Fp.ZERO
		};
		this.ONE = {
			c0: Fp.ONE,
			c1: Fp.ZERO
		};
		this.Fp_NONRESIDUE = Fp.create(opts.NONRESIDUE || BigInt(-1));
		this.Fp_div2 = Fp.div(Fp.ONE, _2n$1);
		this.NONRESIDUE = Fp2fromBigTuple(Fp, opts.FP2_NONRESIDUE);
		this.FROBENIUS_COEFFICIENTS = calcFrobeniusCoefficients(Fp, this.Fp_NONRESIDUE, Fp.ORDER, 2)[0];
		this.mulByB = opts.Fp2mulByB;
		Object.seal(this);
	}
	fromBigTuple(tuple) {
		return Fp2fromBigTuple(this.Fp, tuple);
	}
	create(num) {
		return num;
	}
	isValid({ c0, c1 }) {
		function isValidC(num, ORDER) {
			return typeof num === "bigint" && _0n$1 <= num && num < ORDER;
		}
		return isValidC(c0, this.ORDER) && isValidC(c1, this.ORDER);
	}
	is0({ c0, c1 }) {
		return this.Fp.is0(c0) && this.Fp.is0(c1);
	}
	isValidNot0(num) {
		return !this.is0(num) && this.isValid(num);
	}
	eql({ c0, c1 }, { c0: r0, c1: r1 }) {
		return this.Fp.eql(c0, r0) && this.Fp.eql(c1, r1);
	}
	neg({ c0, c1 }) {
		return {
			c0: this.Fp.neg(c0),
			c1: this.Fp.neg(c1)
		};
	}
	pow(num, power) {
		return FpPow(this, num, power);
	}
	invertBatch(nums) {
		return FpInvertBatch(this, nums);
	}
	add(f1, f2) {
		const { c0, c1 } = f1;
		const { c0: r0, c1: r1 } = f2;
		return {
			c0: this.Fp.add(c0, r0),
			c1: this.Fp.add(c1, r1)
		};
	}
	sub({ c0, c1 }, { c0: r0, c1: r1 }) {
		return {
			c0: this.Fp.sub(c0, r0),
			c1: this.Fp.sub(c1, r1)
		};
	}
	mul({ c0, c1 }, rhs) {
		const { Fp } = this;
		if (typeof rhs === "bigint") return {
			c0: Fp.mul(c0, rhs),
			c1: Fp.mul(c1, rhs)
		};
		const { c0: r0, c1: r1 } = rhs;
		let t1 = Fp.mul(c0, r0);
		let t2 = Fp.mul(c1, r1);
		return {
			c0: Fp.sub(t1, t2),
			c1: Fp.sub(Fp.mul(Fp.add(c0, c1), Fp.add(r0, r1)), Fp.add(t1, t2))
		};
	}
	sqr({ c0, c1 }) {
		const { Fp } = this;
		const a = Fp.add(c0, c1);
		const b = Fp.sub(c0, c1);
		const c = Fp.add(c0, c0);
		return {
			c0: Fp.mul(a, b),
			c1: Fp.mul(c, c1)
		};
	}
	addN(a, b) {
		return this.add(a, b);
	}
	subN(a, b) {
		return this.sub(a, b);
	}
	mulN(a, b) {
		return this.mul(a, b);
	}
	sqrN(a) {
		return this.sqr(a);
	}
	div(lhs, rhs) {
		const { Fp } = this;
		return this.mul(lhs, typeof rhs === "bigint" ? Fp.inv(Fp.create(rhs)) : this.inv(rhs));
	}
	inv({ c0: a, c1: b }) {
		const { Fp } = this;
		const factor = Fp.inv(Fp.create(a * a + b * b));
		return {
			c0: Fp.mul(factor, Fp.create(a)),
			c1: Fp.mul(factor, Fp.create(-b))
		};
	}
	sqrt(num) {
		const { Fp } = this;
		const Fp2 = this;
		const { c0, c1 } = num;
		if (Fp.is0(c1)) if (FpLegendre(Fp, c0) === 1) return Fp2.create({
			c0: Fp.sqrt(c0),
			c1: Fp.ZERO
		});
		else return Fp2.create({
			c0: Fp.ZERO,
			c1: Fp.sqrt(Fp.div(c0, this.Fp_NONRESIDUE))
		});
		const a = Fp.sqrt(Fp.sub(Fp.sqr(c0), Fp.mul(Fp.sqr(c1), this.Fp_NONRESIDUE)));
		let d = Fp.mul(Fp.add(a, c0), this.Fp_div2);
		if (FpLegendre(Fp, d) === -1) d = Fp.sub(d, a);
		const a0 = Fp.sqrt(d);
		const candidateSqrt = Fp2.create({
			c0: a0,
			c1: Fp.div(Fp.mul(c1, this.Fp_div2), a0)
		});
		if (!Fp2.eql(Fp2.sqr(candidateSqrt), num)) throw new Error("Cannot find square root");
		const x1 = candidateSqrt;
		const x2 = Fp2.neg(x1);
		const { re: re1, im: im1 } = Fp2.reim(x1);
		const { re: re2, im: im2 } = Fp2.reim(x2);
		if (im1 > im2 || im1 === im2 && re1 > re2) return x1;
		return x2;
	}
	isOdd(x) {
		const { re: x0, im: x1 } = this.reim(x);
		const sign_0 = x0 % _2n$1;
		const zero_0 = x0 === _0n$1;
		const sign_1 = x1 % _2n$1;
		return BigInt(sign_0 || zero_0 && sign_1) == _1n$1;
	}
	fromBytes(b) {
		const { Fp } = this;
		if (b.length !== this.BYTES) throw new Error("fromBytes invalid length=" + b.length);
		return {
			c0: Fp.fromBytes(b.subarray(0, Fp.BYTES)),
			c1: Fp.fromBytes(b.subarray(Fp.BYTES))
		};
	}
	toBytes({ c0, c1 }) {
		return concatBytes(this.Fp.toBytes(c0), this.Fp.toBytes(c1));
	}
	cmov({ c0, c1 }, { c0: r0, c1: r1 }, c) {
		return {
			c0: this.Fp.cmov(c0, r0, c),
			c1: this.Fp.cmov(c1, r1, c)
		};
	}
	reim({ c0, c1 }) {
		return {
			re: c0,
			im: c1
		};
	}
	Fp4Square(a, b) {
		const Fp2 = this;
		const a2 = Fp2.sqr(a);
		const b2 = Fp2.sqr(b);
		return {
			first: Fp2.add(Fp2.mulByNonresidue(b2), a2),
			second: Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(a, b)), a2), b2)
		};
	}
	mulByNonresidue({ c0, c1 }) {
		return this.mul({
			c0,
			c1
		}, this.NONRESIDUE);
	}
	frobeniusMap({ c0, c1 }, power) {
		return {
			c0,
			c1: this.Fp.mul(c1, this.FROBENIUS_COEFFICIENTS[power % 2])
		};
	}
};
var _Field6 = class {
	ORDER;
	BITS;
	BYTES;
	isLE;
	ZERO;
	ONE;
	Fp2;
	FROBENIUS_COEFFICIENTS_1;
	FROBENIUS_COEFFICIENTS_2;
	constructor(Fp2) {
		this.Fp2 = Fp2;
		this.ORDER = Fp2.ORDER;
		this.BITS = 3 * Fp2.BITS;
		this.BYTES = 3 * Fp2.BYTES;
		this.isLE = Fp2.isLE;
		this.ZERO = {
			c0: Fp2.ZERO,
			c1: Fp2.ZERO,
			c2: Fp2.ZERO
		};
		this.ONE = {
			c0: Fp2.ONE,
			c1: Fp2.ZERO,
			c2: Fp2.ZERO
		};
		const { Fp } = Fp2;
		const frob = calcFrobeniusCoefficients(Fp2, Fp2.NONRESIDUE, Fp.ORDER, 6, 2, 3);
		this.FROBENIUS_COEFFICIENTS_1 = frob[0];
		this.FROBENIUS_COEFFICIENTS_2 = frob[1];
		Object.seal(this);
	}
	add({ c0, c1, c2 }, { c0: r0, c1: r1, c2: r2 }) {
		const { Fp2 } = this;
		return {
			c0: Fp2.add(c0, r0),
			c1: Fp2.add(c1, r1),
			c2: Fp2.add(c2, r2)
		};
	}
	sub({ c0, c1, c2 }, { c0: r0, c1: r1, c2: r2 }) {
		const { Fp2 } = this;
		return {
			c0: Fp2.sub(c0, r0),
			c1: Fp2.sub(c1, r1),
			c2: Fp2.sub(c2, r2)
		};
	}
	mul({ c0, c1, c2 }, rhs) {
		const { Fp2 } = this;
		if (typeof rhs === "bigint") return {
			c0: Fp2.mul(c0, rhs),
			c1: Fp2.mul(c1, rhs),
			c2: Fp2.mul(c2, rhs)
		};
		const { c0: r0, c1: r1, c2: r2 } = rhs;
		const t0 = Fp2.mul(c0, r0);
		const t1 = Fp2.mul(c1, r1);
		const t2 = Fp2.mul(c2, r2);
		return {
			c0: Fp2.add(t0, Fp2.mulByNonresidue(Fp2.sub(Fp2.mul(Fp2.add(c1, c2), Fp2.add(r1, r2)), Fp2.add(t1, t2)))),
			c1: Fp2.add(Fp2.sub(Fp2.mul(Fp2.add(c0, c1), Fp2.add(r0, r1)), Fp2.add(t0, t1)), Fp2.mulByNonresidue(t2)),
			c2: Fp2.sub(Fp2.add(t1, Fp2.mul(Fp2.add(c0, c2), Fp2.add(r0, r2))), Fp2.add(t0, t2))
		};
	}
	sqr({ c0, c1, c2 }) {
		const { Fp2 } = this;
		let t0 = Fp2.sqr(c0);
		let t1 = Fp2.mul(Fp2.mul(c0, c1), _2n$1);
		let t3 = Fp2.mul(Fp2.mul(c1, c2), _2n$1);
		let t4 = Fp2.sqr(c2);
		return {
			c0: Fp2.add(Fp2.mulByNonresidue(t3), t0),
			c1: Fp2.add(Fp2.mulByNonresidue(t4), t1),
			c2: Fp2.sub(Fp2.sub(Fp2.add(Fp2.add(t1, Fp2.sqr(Fp2.add(Fp2.sub(c0, c1), c2))), t3), t0), t4)
		};
	}
	addN(a, b) {
		return this.add(a, b);
	}
	subN(a, b) {
		return this.sub(a, b);
	}
	mulN(a, b) {
		return this.mul(a, b);
	}
	sqrN(a) {
		return this.sqr(a);
	}
	create(num) {
		return num;
	}
	isValid({ c0, c1, c2 }) {
		const { Fp2 } = this;
		return Fp2.isValid(c0) && Fp2.isValid(c1) && Fp2.isValid(c2);
	}
	is0({ c0, c1, c2 }) {
		const { Fp2 } = this;
		return Fp2.is0(c0) && Fp2.is0(c1) && Fp2.is0(c2);
	}
	isValidNot0(num) {
		return !this.is0(num) && this.isValid(num);
	}
	neg({ c0, c1, c2 }) {
		const { Fp2 } = this;
		return {
			c0: Fp2.neg(c0),
			c1: Fp2.neg(c1),
			c2: Fp2.neg(c2)
		};
	}
	eql({ c0, c1, c2 }, { c0: r0, c1: r1, c2: r2 }) {
		const { Fp2 } = this;
		return Fp2.eql(c0, r0) && Fp2.eql(c1, r1) && Fp2.eql(c2, r2);
	}
	sqrt(_) {
		return notImplemented();
	}
	div(lhs, rhs) {
		const { Fp2 } = this;
		const { Fp } = Fp2;
		return this.mul(lhs, typeof rhs === "bigint" ? Fp.inv(Fp.create(rhs)) : this.inv(rhs));
	}
	pow(num, power) {
		return FpPow(this, num, power);
	}
	invertBatch(nums) {
		return FpInvertBatch(this, nums);
	}
	inv({ c0, c1, c2 }) {
		const { Fp2 } = this;
		let t0 = Fp2.sub(Fp2.sqr(c0), Fp2.mulByNonresidue(Fp2.mul(c2, c1)));
		let t1 = Fp2.sub(Fp2.mulByNonresidue(Fp2.sqr(c2)), Fp2.mul(c0, c1));
		let t2 = Fp2.sub(Fp2.sqr(c1), Fp2.mul(c0, c2));
		let t4 = Fp2.inv(Fp2.add(Fp2.mulByNonresidue(Fp2.add(Fp2.mul(c2, t1), Fp2.mul(c1, t2))), Fp2.mul(c0, t0)));
		return {
			c0: Fp2.mul(t4, t0),
			c1: Fp2.mul(t4, t1),
			c2: Fp2.mul(t4, t2)
		};
	}
	fromBytes(b) {
		const { Fp2 } = this;
		if (b.length !== this.BYTES) throw new Error("fromBytes invalid length=" + b.length);
		const B2 = Fp2.BYTES;
		return {
			c0: Fp2.fromBytes(b.subarray(0, B2)),
			c1: Fp2.fromBytes(b.subarray(B2, B2 * 2)),
			c2: Fp2.fromBytes(b.subarray(2 * B2))
		};
	}
	toBytes({ c0, c1, c2 }) {
		const { Fp2 } = this;
		return concatBytes(Fp2.toBytes(c0), Fp2.toBytes(c1), Fp2.toBytes(c2));
	}
	cmov({ c0, c1, c2 }, { c0: r0, c1: r1, c2: r2 }, c) {
		const { Fp2 } = this;
		return {
			c0: Fp2.cmov(c0, r0, c),
			c1: Fp2.cmov(c1, r1, c),
			c2: Fp2.cmov(c2, r2, c)
		};
	}
	fromBigSix(t) {
		const { Fp2 } = this;
		if (!Array.isArray(t) || t.length !== 6) throw new Error("invalid Fp6 usage");
		return {
			c0: Fp2.fromBigTuple(t.slice(0, 2)),
			c1: Fp2.fromBigTuple(t.slice(2, 4)),
			c2: Fp2.fromBigTuple(t.slice(4, 6))
		};
	}
	frobeniusMap({ c0, c1, c2 }, power) {
		const { Fp2 } = this;
		return {
			c0: Fp2.frobeniusMap(c0, power),
			c1: Fp2.mul(Fp2.frobeniusMap(c1, power), this.FROBENIUS_COEFFICIENTS_1[power % 6]),
			c2: Fp2.mul(Fp2.frobeniusMap(c2, power), this.FROBENIUS_COEFFICIENTS_2[power % 6])
		};
	}
	mulByFp2({ c0, c1, c2 }, rhs) {
		const { Fp2 } = this;
		return {
			c0: Fp2.mul(c0, rhs),
			c1: Fp2.mul(c1, rhs),
			c2: Fp2.mul(c2, rhs)
		};
	}
	mulByNonresidue({ c0, c1, c2 }) {
		const { Fp2 } = this;
		return {
			c0: Fp2.mulByNonresidue(c2),
			c1: c0,
			c2: c1
		};
	}
	mul1({ c0, c1, c2 }, b1) {
		const { Fp2 } = this;
		return {
			c0: Fp2.mulByNonresidue(Fp2.mul(c2, b1)),
			c1: Fp2.mul(c0, b1),
			c2: Fp2.mul(c1, b1)
		};
	}
	mul01({ c0, c1, c2 }, b0, b1) {
		const { Fp2 } = this;
		let t0 = Fp2.mul(c0, b0);
		let t1 = Fp2.mul(c1, b1);
		return {
			c0: Fp2.add(Fp2.mulByNonresidue(Fp2.sub(Fp2.mul(Fp2.add(c1, c2), b1), t1)), t0),
			c1: Fp2.sub(Fp2.sub(Fp2.mul(Fp2.add(b0, b1), Fp2.add(c0, c1)), t0), t1),
			c2: Fp2.add(Fp2.sub(Fp2.mul(Fp2.add(c0, c2), b0), t0), t1)
		};
	}
};
var _Field12 = class {
	ORDER;
	BITS;
	BYTES;
	isLE;
	ZERO;
	ONE;
	Fp6;
	FROBENIUS_COEFFICIENTS;
	X_LEN;
	finalExponentiate;
	constructor(Fp6, opts) {
		const { Fp2 } = Fp6;
		const { Fp } = Fp2;
		this.Fp6 = Fp6;
		this.ORDER = Fp2.ORDER;
		this.BITS = 2 * Fp6.BITS;
		this.BYTES = 2 * Fp6.BYTES;
		this.isLE = Fp6.isLE;
		this.ZERO = {
			c0: Fp6.ZERO,
			c1: Fp6.ZERO
		};
		this.ONE = {
			c0: Fp6.ONE,
			c1: Fp6.ZERO
		};
		this.FROBENIUS_COEFFICIENTS = calcFrobeniusCoefficients(Fp2, Fp2.NONRESIDUE, Fp.ORDER, 12, 1, 6)[0];
		this.X_LEN = opts.X_LEN;
		this.finalExponentiate = opts.Fp12finalExponentiate;
	}
	create(num) {
		return num;
	}
	isValid({ c0, c1 }) {
		const { Fp6 } = this;
		return Fp6.isValid(c0) && Fp6.isValid(c1);
	}
	is0({ c0, c1 }) {
		const { Fp6 } = this;
		return Fp6.is0(c0) && Fp6.is0(c1);
	}
	isValidNot0(num) {
		return !this.is0(num) && this.isValid(num);
	}
	neg({ c0, c1 }) {
		const { Fp6 } = this;
		return {
			c0: Fp6.neg(c0),
			c1: Fp6.neg(c1)
		};
	}
	eql({ c0, c1 }, { c0: r0, c1: r1 }) {
		const { Fp6 } = this;
		return Fp6.eql(c0, r0) && Fp6.eql(c1, r1);
	}
	sqrt(_) {
		notImplemented();
	}
	inv({ c0, c1 }) {
		const { Fp6 } = this;
		let t = Fp6.inv(Fp6.sub(Fp6.sqr(c0), Fp6.mulByNonresidue(Fp6.sqr(c1))));
		return {
			c0: Fp6.mul(c0, t),
			c1: Fp6.neg(Fp6.mul(c1, t))
		};
	}
	div(lhs, rhs) {
		const { Fp6 } = this;
		const { Fp2 } = Fp6;
		const { Fp } = Fp2;
		return this.mul(lhs, typeof rhs === "bigint" ? Fp.inv(Fp.create(rhs)) : this.inv(rhs));
	}
	pow(num, power) {
		return FpPow(this, num, power);
	}
	invertBatch(nums) {
		return FpInvertBatch(this, nums);
	}
	add({ c0, c1 }, { c0: r0, c1: r1 }) {
		const { Fp6 } = this;
		return {
			c0: Fp6.add(c0, r0),
			c1: Fp6.add(c1, r1)
		};
	}
	sub({ c0, c1 }, { c0: r0, c1: r1 }) {
		const { Fp6 } = this;
		return {
			c0: Fp6.sub(c0, r0),
			c1: Fp6.sub(c1, r1)
		};
	}
	mul({ c0, c1 }, rhs) {
		const { Fp6 } = this;
		if (typeof rhs === "bigint") return {
			c0: Fp6.mul(c0, rhs),
			c1: Fp6.mul(c1, rhs)
		};
		let { c0: r0, c1: r1 } = rhs;
		let t1 = Fp6.mul(c0, r0);
		let t2 = Fp6.mul(c1, r1);
		return {
			c0: Fp6.add(t1, Fp6.mulByNonresidue(t2)),
			c1: Fp6.sub(Fp6.mul(Fp6.add(c0, c1), Fp6.add(r0, r1)), Fp6.add(t1, t2))
		};
	}
	sqr({ c0, c1 }) {
		const { Fp6 } = this;
		let ab = Fp6.mul(c0, c1);
		return {
			c0: Fp6.sub(Fp6.sub(Fp6.mul(Fp6.add(Fp6.mulByNonresidue(c1), c0), Fp6.add(c0, c1)), ab), Fp6.mulByNonresidue(ab)),
			c1: Fp6.add(ab, ab)
		};
	}
	addN(a, b) {
		return this.add(a, b);
	}
	subN(a, b) {
		return this.sub(a, b);
	}
	mulN(a, b) {
		return this.mul(a, b);
	}
	sqrN(a) {
		return this.sqr(a);
	}
	fromBytes(b) {
		const { Fp6 } = this;
		if (b.length !== this.BYTES) throw new Error("fromBytes invalid length=" + b.length);
		return {
			c0: Fp6.fromBytes(b.subarray(0, Fp6.BYTES)),
			c1: Fp6.fromBytes(b.subarray(Fp6.BYTES))
		};
	}
	toBytes({ c0, c1 }) {
		const { Fp6 } = this;
		return concatBytes(Fp6.toBytes(c0), Fp6.toBytes(c1));
	}
	cmov({ c0, c1 }, { c0: r0, c1: r1 }, c) {
		const { Fp6 } = this;
		return {
			c0: Fp6.cmov(c0, r0, c),
			c1: Fp6.cmov(c1, r1, c)
		};
	}
	fromBigTwelve(t) {
		const { Fp6 } = this;
		return {
			c0: Fp6.fromBigSix(t.slice(0, 6)),
			c1: Fp6.fromBigSix(t.slice(6, 12))
		};
	}
	frobeniusMap(lhs, power) {
		const { Fp6 } = this;
		const { Fp2 } = Fp6;
		const { c0, c1, c2 } = Fp6.frobeniusMap(lhs.c1, power);
		const coeff = this.FROBENIUS_COEFFICIENTS[power % 12];
		return {
			c0: Fp6.frobeniusMap(lhs.c0, power),
			c1: Fp6.create({
				c0: Fp2.mul(c0, coeff),
				c1: Fp2.mul(c1, coeff),
				c2: Fp2.mul(c2, coeff)
			})
		};
	}
	mulByFp2({ c0, c1 }, rhs) {
		const { Fp6 } = this;
		return {
			c0: Fp6.mulByFp2(c0, rhs),
			c1: Fp6.mulByFp2(c1, rhs)
		};
	}
	conjugate({ c0, c1 }) {
		return {
			c0,
			c1: this.Fp6.neg(c1)
		};
	}
	mul014({ c0, c1 }, o0, o1, o4) {
		const { Fp6 } = this;
		const { Fp2 } = Fp6;
		let t0 = Fp6.mul01(c0, o0, o1);
		let t1 = Fp6.mul1(c1, o4);
		return {
			c0: Fp6.add(Fp6.mulByNonresidue(t1), t0),
			c1: Fp6.sub(Fp6.sub(Fp6.mul01(Fp6.add(c1, c0), o0, Fp2.add(o1, o4)), t0), t1)
		};
	}
	mul034({ c0, c1 }, o0, o3, o4) {
		const { Fp6 } = this;
		const { Fp2 } = Fp6;
		const a = Fp6.create({
			c0: Fp2.mul(c0.c0, o0),
			c1: Fp2.mul(c0.c1, o0),
			c2: Fp2.mul(c0.c2, o0)
		});
		const b = Fp6.mul01(c1, o3, o4);
		const e = Fp6.mul01(Fp6.add(c0, c1), Fp2.add(o0, o3), o4);
		return {
			c0: Fp6.add(Fp6.mulByNonresidue(b), a),
			c1: Fp6.sub(e, Fp6.add(a, b))
		};
	}
	_cyclotomicSquare({ c0, c1 }) {
		const { Fp6 } = this;
		const { Fp2 } = Fp6;
		const { c0: c0c0, c1: c0c1, c2: c0c2 } = c0;
		const { c0: c1c0, c1: c1c1, c2: c1c2 } = c1;
		const { first: t3, second: t4 } = Fp2.Fp4Square(c0c0, c1c1);
		const { first: t5, second: t6 } = Fp2.Fp4Square(c1c0, c0c2);
		const { first: t7, second: t8 } = Fp2.Fp4Square(c0c1, c1c2);
		const t9 = Fp2.mulByNonresidue(t8);
		return {
			c0: Fp6.create({
				c0: Fp2.add(Fp2.mul(Fp2.sub(t3, c0c0), _2n$1), t3),
				c1: Fp2.add(Fp2.mul(Fp2.sub(t5, c0c1), _2n$1), t5),
				c2: Fp2.add(Fp2.mul(Fp2.sub(t7, c0c2), _2n$1), t7)
			}),
			c1: Fp6.create({
				c0: Fp2.add(Fp2.mul(Fp2.add(t9, c1c0), _2n$1), t9),
				c1: Fp2.add(Fp2.mul(Fp2.add(t4, c1c1), _2n$1), t4),
				c2: Fp2.add(Fp2.mul(Fp2.add(t6, c1c2), _2n$1), t6)
			})
		};
	}
	_cyclotomicExp(num, n) {
		let z = this.ONE;
		for (let i = this.X_LEN - 1; i >= 0; i--) {
			z = this._cyclotomicSquare(z);
			if (bitGet(n, i)) z = this.mul(z, num);
		}
		return z;
	}
};
function tower12(opts) {
	const Fp = Field(opts.ORDER);
	const Fp2 = new _Field2(Fp, opts);
	const Fp6 = new _Field6(Fp2);
	return {
		Fp,
		Fp2,
		Fp6,
		Fp12: new _Field12(Fp6, opts)
	};
}
//#endregion
//#region node_modules/@noble/curves/bn254.js
/**
* bn254, previously known as alt_bn_128, when it had 128-bit security.

Barbulescu-Duquesne 2017 shown it's weaker: just about 100 bits,
so the naming has been adjusted to its prime bit count:
https://hal.science/hal-01534101/file/main.pdf.
Compatible with EIP-196 and EIP-197.

There are huge compatibility issues in the ecosystem:

1. Different libraries call it in different ways: "bn254", "bn256", "alt_bn128", "bn128".
2. libff has bn128, but it's a different curve with different G2:
https://github.com/scipr-lab/libff/blob/a44f482e18b8ac04d034c193bd9d7df7817ad73f/libff/algebra/curves/bn128/bn128_init.cpp#L166-L169
3. halo2curves bn256 is also incompatible and returns different outputs

We don't implement Point methods toHex / toBytes.
To work around this limitation, has to initialize points on their own from BigInts.
Reason it's not implemented is because [there is no standard](https://github.com/privacy-scaling-explorations/halo2curves/issues/109).
Points of divergence:

- Endianness: LE vs BE (byte-swapped)
- Flags as first hex bits (similar to BLS) vs no-flags
- Imaginary part last in G2 vs first (c0, c1 vs c1, c0)

The goal of our implementation is to support "Ethereum" variant of the curve,
because it at least has specs:

- EIP196 (https://eips.ethereum.org/EIPS/eip-196) describes bn254 ECADD and ECMUL opcodes for EVM
- EIP197 (https://eips.ethereum.org/EIPS/eip-197) describes bn254 pairings
- It's hard: EIPs don't have proper tests. EIP-197 returns boolean output instead of Fp12
- The existing implementations are bad. Some are deprecated:
- https://github.com/paritytech/bn (old version)
- https://github.com/ewasm/ethereum-bn128.rs (uses paritytech/bn)
- https://github.com/zcash-hackworks/bn
- https://github.com/arkworks-rs/curves/blob/master/bn254/src/lib.rs
- Python implementations use different towers and produce different Fp12 outputs:
- https://github.com/ethereum/py_pairing
- https://github.com/ethereum/py_ecc/tree/main/py_ecc/bn128
- Points are encoded differently in different implementations

### Params
Seed (X): 4965661367192848881
Fr: (36x⁴+36x³+18x²+6x+1)
Fp: (36x⁴+36x³+24x²+6x+1)
(E  / Fp ): Y² = X³+3
(Et / Fp²): Y² = X³+3/(u+9) (D-type twist)
Ate loop size: 6x+2

### Towers
- Fp²[u] = Fp/u²+1
- Fp⁶[v] = Fp²/v³-9-u
- Fp¹²[w] = Fp⁶/w²-v

* @module
*/
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3);
var _6n = BigInt(6);
var BN_X = BigInt("4965661367192848881");
var BN_X_LEN = bitLen(BN_X);
var SIX_X_SQUARED = _6n * BN_X ** _2n;
var bn254_G1_CURVE = {
	p: BigInt("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"),
	n: BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"),
	h: _1n,
	a: _0n,
	b: _3n,
	Gx: _1n,
	Gy: BigInt(2)
};
var bn254_Fr = Field(bn254_G1_CURVE.n);
var Fp2B = {
	c0: BigInt("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
	c1: BigInt("266929791119991161246907387137283842545076965332900288569378510910307636690")
};
var { Fp, Fp2: Fp2$1, Fp6, Fp12: Fp12$1 } = tower12({
	ORDER: bn254_G1_CURVE.p,
	X_LEN: BN_X_LEN,
	FP2_NONRESIDUE: [BigInt(9), _1n],
	Fp2mulByB: (num) => Fp2$1.mul(num, Fp2B),
	Fp12finalExponentiate: (num) => {
		const powMinusX = (num) => Fp12$1.conjugate(Fp12$1._cyclotomicExp(num, BN_X));
		const r0 = Fp12$1.mul(Fp12$1.conjugate(num), Fp12$1.inv(num));
		const r = Fp12$1.mul(Fp12$1.frobeniusMap(r0, 2), r0);
		const y1 = Fp12$1._cyclotomicSquare(powMinusX(r));
		const y2 = Fp12$1.mul(Fp12$1._cyclotomicSquare(y1), y1);
		const y4 = powMinusX(y2);
		const y6 = powMinusX(Fp12$1._cyclotomicSquare(y4));
		const y8 = Fp12$1.mul(Fp12$1.mul(Fp12$1.conjugate(y6), y4), Fp12$1.conjugate(y2));
		const y9 = Fp12$1.mul(y8, y1);
		return Fp12$1.mul(Fp12$1.frobeniusMap(Fp12$1.mul(Fp12$1.conjugate(r), y9), 3), Fp12$1.mul(Fp12$1.frobeniusMap(y8, 2), Fp12$1.mul(Fp12$1.frobeniusMap(y9, 1), Fp12$1.mul(Fp12$1.mul(y8, y4), r))));
	}
});
var { G2psi, psi } = psiFrobenius(Fp, Fp2$1, Fp2$1.NONRESIDUE);
var _postPrecompute = (Rx, Ry, Rz, Qx, Qy, pointAdd) => {
	const q = psi(Qx, Qy);
	({Rx, Ry, Rz} = pointAdd(Rx, Ry, Rz, q[0], q[1]));
	const q2 = psi(q[0], q[1]);
	pointAdd(Rx, Ry, Rz, q2[0], Fp2$1.neg(q2[1]));
};
var bn254_G2_CURVE = {
	p: Fp2$1.ORDER,
	n: bn254_G1_CURVE.n,
	h: BigInt("0x30644e72e131a029b85045b68181585e06ceecda572a2489345f2299c0f9fa8d"),
	a: Fp2$1.ZERO,
	b: Fp2B,
	Gx: Fp2$1.fromBigTuple([BigInt("10857046999023057135944570762232829481370756359578518086990519993285655852781"), BigInt("11559732032986387107991004021392285783925812861821192530917403151452391805634")]),
	Gy: Fp2$1.fromBigTuple([BigInt("8495653923123431417604973247489272438418190587263600148770280649306958101930"), BigInt("4082367875863433681332203403145435568316851327593401208105741076214120093531")])
};
/**
* bn254 (a.k.a. alt_bn128) pairing-friendly curve.
* Contains G1 / G2 operations and pairings.
*/
var bn254 = blsBasic({
	Fp,
	Fp2: Fp2$1,
	Fp6,
	Fp12: Fp12$1,
	Fr: bn254_Fr
}, weierstrass(bn254_G1_CURVE, {
	Fp,
	Fn: bn254_Fr,
	allowInfinityPoint: true
}), weierstrass(bn254_G2_CURVE, {
	Fp: Fp2$1,
	Fn: bn254_Fr,
	allowInfinityPoint: true,
	isTorsionFree: (c, P) => P.multiplyUnsafe(SIX_X_SQUARED).equals(G2psi(c, P))
}), {
	ateLoopSize: BN_X * _6n + _2n,
	r: bn254_Fr.ORDER,
	xNegative: false,
	twistType: "divisive",
	postPrecompute: _postPrecompute
});
//#endregion
//#region src/common.ts
var Groth16 = "groth16";
var AuthV2Circuit = "authV2";
var AuthV3Circuit = "authV3";
var AuthV3_8_32Circuit = "authV3-8-32";
var textDecoder = new TextDecoder();
var ZERO_BIGINT = BigInt(0);
var Fp2 = bn254.fields.Fp2;
var Fp12 = bn254.fields.Fp12;
async function prove(inputs, provingKey, wasm) {
	const witnessCalculator = await witnessBuilder(wasm);
	const jsonString = new TextDecoder().decode(inputs);
	const parsedData = JSON.parse(jsonString);
	const wtnsBytes = await witnessCalculator.calculateWTNSBin(parsedData, 0);
	const { proof, publicSignals } = await groth16.prove(provingKey, wtnsBytes);
	return {
		proof,
		pub_signals: publicSignals
	};
}
var [G1PP, G2PP] = [bn254.G1.Point, bn254.G2.Point];
var toG1 = ([x, y]) => G1PP.fromAffine({
	x: BigInt(x),
	y: BigInt(y)
});
var toG2 = ([[x0, y0], [x1, y1]]) => {
	return G2PP.fromAffine({
		x: Fp2.fromBigTuple([BigInt(x0), BigInt(y0)]),
		y: Fp2.fromBigTuple([BigInt(x1), BigInt(y1)])
	});
};
async function verify(messageHash, proof, verificationKey, unmarshall) {
	const outputs = unmarshall(proof.pub_signals);
	const expectedChallenge = fromBigEndian(messageHash);
	if (outputs.challenge !== expectedChallenge) throw new Error("challenge is not equal to message hash");
	return verifyGroth16Proof(proof, JSON.parse(textDecoder.decode(verificationKey)));
}
function verifyGroth16Proof(zkp, vk) {
	if (!vk.IC) throw new Error(`verification file doesn't exist for circuit`);
	const { proof, pub_signals } = zkp;
	if (pub_signals.length + 1 !== vk.IC.length) throw new Error(`Invalid number of public signals, expected ${vk.IC.length - 1} but got ${pub_signals.length}`);
	let cpub = G1PP.ZERO;
	for (let i = 0; i < pub_signals.length; i++) {
		if (BigInt(pub_signals[i]) < ZERO_BIGINT || BigInt(pub_signals[i]) >= bn254.fields.Fr.ORDER) throw new Error(`Input value is not in the field ${bn254.fields.Fr.ORDER}`);
		if (BigInt(pub_signals[i]) !== ZERO_BIGINT) {
			const [x, y] = vk.IC[i + 1].map(BigInt);
			cpub = cpub.add(G1PP.fromAffine({
				x,
				y
			}).multiply(BigInt(pub_signals[i])));
		}
	}
	cpub = cpub.add(toG1(vk.IC[0]));
	const newRes = bn254.pairingBatch([
		{
			g1: toG1(proof.pi_a).negate(),
			g2: toG2(proof.pi_b)
		},
		{
			g1: cpub,
			g2: toG2(vk.vk_gamma_2)
		},
		{
			g1: toG1(proof.pi_c),
			g2: toG2(vk.vk_delta_2)
		},
		{
			g1: toG1(vk.vk_alpha_1),
			g2: toG2(vk.vk_beta_2)
		}
	]);
	return Fp12.eql(newRes, Fp12.ONE);
}
new ProvingMethodAlg(Groth16, AuthV2Circuit);
var provingMethodGroth16AuthV2Instance = new class ProvingMethodGroth16AuthV2 {
	static curveName = "bn128";
	constructor(methodAlg, opts) {
		this.methodAlg = methodAlg;
		this.opts = opts;
	}
	get alg() {
		return this.methodAlg.alg;
	}
	get circuitId() {
		return this.methodAlg.circuitId;
	}
	get supportedCircuits() {
		return [...new Set([this.methodAlg.circuitId, ...this.opts?.circuitSubVersions || []])];
	}
	async verify(messageHash, proof, verificationKey) {
		return verify(messageHash, proof, verificationKey, this.unmarshall);
	}
	async prove(inputs, provingKey, wasm) {
		const zkProof = await prove(inputs, provingKey, wasm);
		await this.terminateCurve();
		return zkProof;
	}
	async terminateCurve() {
		(await getCurveFromName(ProvingMethodGroth16AuthV2.curveName)).terminate();
	}
	unmarshall(pubSignals) {
		const len = 3;
		if (pubSignals.length !== len) throw new Error(`invalid number of Output values expected ${len} got ${pubSignals.length}`);
		return {
			userID: Id.fromBigInt(BigInt(pubSignals[0])),
			challenge: BigInt(pubSignals[1]),
			GISTRoot: Hash.fromString(pubSignals[2])
		};
	}
}(new ProvingMethodAlg(Groth16, AuthV2Circuit));
new ProvingMethodAlg(Groth16, AuthV3Circuit);
new ProvingMethodAlg(Groth16, AuthV3_8_32Circuit);
var ProvingMethodGroth16AuthV3 = class ProvingMethodGroth16AuthV3 {
	static curveName = "bn128";
	constructor(methodAlg, opts) {
		this.methodAlg = methodAlg;
		this.opts = opts;
	}
	get alg() {
		return this.methodAlg.alg;
	}
	get circuitId() {
		return this.methodAlg.circuitId;
	}
	get supportedCircuits() {
		return [...new Set([this.methodAlg.circuitId, ...this.opts?.circuitSubVersions || []])];
	}
	async verify(messageHash, proof, verificationKey) {
		return verify(messageHash, proof, verificationKey, this.unmarshall);
	}
	async prove(inputs, provingKey, wasm) {
		const zkProof = await prove(inputs, provingKey, wasm);
		await this.terminateCurve();
		return zkProof;
	}
	async terminateCurve() {
		(await getCurveFromName(ProvingMethodGroth16AuthV3.curveName)).terminate();
	}
	unmarshall(pubSignals) {
		const len = 3;
		if (pubSignals.length !== len) throw new Error(`invalid number of Output values expected ${len} got ${pubSignals.length}`);
		return {
			userID: Id.fromBigInt(BigInt(pubSignals[0])),
			challenge: BigInt(pubSignals[1]),
			GISTRoot: Hash.fromString(pubSignals[2])
		};
	}
};
var provingMethodGroth16AuthV3Instance = new ProvingMethodGroth16AuthV3(new ProvingMethodAlg(Groth16, AuthV3Circuit), { circuitSubVersions: ["authV3-8-32"] });
var provingMethodGroth16AuthV3_8_32Instance = new ProvingMethodGroth16AuthV3(new ProvingMethodAlg(Groth16, AuthV3_8_32Circuit));
//#endregion
//#region src/index.ts
registerProvingMethod(provingMethodGroth16AuthV2Instance.methodAlg, () => provingMethodGroth16AuthV2Instance);
registerProvingMethod(provingMethodGroth16AuthV3Instance.methodAlg, () => provingMethodGroth16AuthV3Instance);
registerProvingMethod(provingMethodGroth16AuthV3_8_32Instance.methodAlg, () => provingMethodGroth16AuthV3_8_32Instance);
var proving = {
	registerProvingMethod,
	getProvingMethod,
	provingMethodGroth16AuthV2Instance,
	provingMethodGroth16AuthV3Instance,
	provingMethodGroth16AuthV3_8_32Instance
};
//#endregion
export { Header, ProvingMethodAlg, Token, hash, proving, verifyGroth16Proof, witnessBuilder };

//# sourceMappingURL=index.js.map