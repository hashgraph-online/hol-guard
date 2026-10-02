"use strict";

const assert = require("node:assert/strict");

function verifyForge() {
  const forge = require("node-forge");
  const keys = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 3 });
  const md = forge.md.sha256.create();
  md.update("MCPB RSA verification regression", "utf8");
  const digest = md.digest().getBytes();
  assert.equal(keys.publicKey.verify(digest, keys.privateKey.sign(md)), true);
  assert.equal(keys.publicKey.verify("\x00".repeat(32), keys.privateKey.sign(md)), false);

  const { asn1 } = forge;
  const universal = asn1.Class.UNIVERSAL;
  const oid = () => asn1.create(universal, asn1.Type.OID, false, asn1.oidToDer(forge.oids.sha256).getBytes());
  const parameter = () => asn1.create(universal, asn1.Type.NULL, false, "");
  const garbage = () => asn1.create(universal, asn1.Type.OCTETSTRING, false, "unconsumed bytes");
  const encode = (algorithm) => asn1.toDer(asn1.create(universal, asn1.Type.SEQUENCE, true, [
    asn1.create(universal, asn1.Type.SEQUENCE, true, algorithm),
    asn1.create(universal, asn1.Type.OCTETSTRING, false, digest),
  ])).getBytes();

  for (const algorithm of [[oid()], [oid(), parameter()]]) {
    const signature = keys.privateKey.sign(encode(algorithm), "NONE");
    assert.equal(keys.publicKey.verify(digest, signature), true);
  }
  for (const algorithm of [
    [oid(), parameter(), garbage()],
    [oid(), garbage()],
    [oid(), asn1.create(universal, asn1.Type.NULL, false, "nonempty")],
  ]) {
    const signature = keys.privateKey.sign(encode(algorithm), "NONE");
    assert.throws(() => keys.publicKey.verify(digest, signature), /valid RSASSA-PKCS1-v1_5/);
  }
  console.log("RSA verification: canonical signatures pass; mismatched digest and three malformed AlgorithmIdentifiers rejected.");
}

module.exports = verifyForge;
if (require.main === module) verifyForge();
