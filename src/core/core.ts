import CryptoJS from 'crypto-js';
import { toBufferLE } from 'bigint-buffer';

export class Core {
  static intToBytes(int: bigint): Uint8Array {
    return Uint8Array.from(toBufferLE(int, 31));
  }

  static checkChecksum(bytes: Uint8Array): boolean {
    const { typ, genesis, checksum } = Core.decomposeBytes(bytes);
    if (
      !checksum.length ||
      JSON.stringify(Uint8Array.from([0, 0])) === JSON.stringify(checksum)
    ) {
      return false;
    }

    const c = Core.calculateChecksum(typ, genesis);
    return JSON.stringify(c) === JSON.stringify(checksum);
  }

  static decomposeBytes(b: Uint8Array): {
    typ: Uint8Array;
    genesis: Uint8Array;
    checksum: Uint8Array;
  } {
    const offset = 2;
    const len = b.length - offset;
    return {
      typ: b.slice(0, offset),
      genesis: b.slice(offset, len),
      checksum: b.slice(-offset),
    };
  }

  static calculateChecksum(typ: Uint8Array, genesis: Uint8Array): Uint8Array {
    const toChecksum = new Uint8Array([...typ, ...genesis]);
    const s = toChecksum.reduce((acc, cur) => acc + cur, 0);
    const checksum = [];
    checksum[0] = s >> 8;
    checksum[1] = s & 0xff;
    return Uint8Array.from(checksum);
  }

  static hashBytes(str: string): Uint8Array {
    const hash = CryptoJS.SHA256(str);
    const buffer = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex');
    return new Uint8Array(buffer);
  }

  static hexToBytes(str: string): Uint8Array {
    const buffer = Buffer.from('0001', 'hex');
    return Uint8Array.from(buffer);
  }

  static bytesToHex(bytes: Uint8Array) {
    let hex: string[] = [];
    for (let i = 0; i < bytes.length; i++) {
      const current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
      hex.push((current >>> 4).toString(16));
      hex.push((current & 0xf).toString(16));
    }
    return hex.join('');
  }
}