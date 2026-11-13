// Stellar strkey encoding (SEP-23), enough to compare an address in the manifest
// with the raw key bytes an indexer stores.
//
// A "raw key" here is the version byte followed by the payload, without the
// checksum: 33 bytes for a G address, 73 or more for a signed payload.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// CRC-16/XMODEM, as strkey uses.
export function crc16(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function base32Encode(bytes) {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(buffer >> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

function base32Decode(text) {
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const char of text) {
    const value = ALPHABET.indexOf(char);
    if (value === -1) throw new Error(`not a base32 character: ${char}`);
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0) throw new Error("non-zero padding bits");
  return Buffer.from(out);
}

// Raw key to strkey. Does not check that the payload length suits the version
// byte, so a truncated key still encodes and can be shown in a report.
export function encodeStrkey(rawKey) {
  const checksum = Buffer.alloc(2);
  checksum.writeUInt16LE(crc16(rawKey));
  return base32Encode(Buffer.concat([rawKey, checksum]));
}

// Strkey to raw key. Throws when the checksum does not match.
export function decodeStrkey(text) {
  const bytes = base32Decode(text);
  if (bytes.length < 3) throw new Error("strkey too short");
  const rawKey = bytes.subarray(0, -2);
  if (bytes.readUInt16LE(bytes.length - 2) !== crc16(rawKey)) throw new Error("strkey checksum mismatch");
  return rawKey;
}
