
36010: ECPair
42595: CipherBase("digest")


function bip32RootKey() {
  var I = createHmac('sha512', HDNode.MASTER_SECRET).update(seed).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  var pIL = BigInteger.fromBuffer(IL)
  var keyPair = new ECPair(pIL, null, {
    network: network
  })

  return new HDNode(keyPair, IR)
}




function calcBip32ExtendedKey(path) {  //"m/44'/0'/0'/0"
    // Check there's a root key to derive from
    if (!bip32RootKey) {
        return bip32RootKey;
    }
    var extendedKey = bip32RootKey;
    // Derive the key from the path
    var pathBits = path.split("/");
    for (var i=0; i<pathBits.length; i++) {
        var bit = pathBits[i];
        var index = parseInt(bit);
        if (isNaN(index)) {
            continue;
        }
        var hardened = bit[bit.length-1] == "'";
        var isPriv = !(extendedKey.isNeutered());
        var invalidDerivationPath = hardened && !isPriv;
        if (invalidDerivationPath) {
            extendedKey = null;
        }
        else if (hardened) {
            extendedKey = extendedKey.deriveHardened(index);
        }
        else {
            extendedKey = extendedKey.derive(index);
        }
    }
    return extendedKey
}



// "Bitcoin seed"
const bitcoinSeed = new Uint8Array([66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100]).buffer


window.crypto.subtle.importKey(
  "raw", 
  bitcoinSeed,
  {
    name: "HMAC",
    hash: "SHA-512"
  }
  true,
  ["sign"]
).then((key) => {
  console.log(key)
  window.crypto.subtle.sign(
    {
      name: "HMAC"
    },
    key,
    data
  )
})