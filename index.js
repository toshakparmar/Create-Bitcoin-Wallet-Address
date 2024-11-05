// Add Dependencies..
const bip39 = require("bip39");
const hdkey = require("hdkey");
const createHash = require("create-hash");
const bs58check = require("bs58check");

// Create the checksum of the mnemonic
const mnemonic = "crazy horse battery staple fresh dolittle height";
const checkSum = Buffer.from([0x6f]);

// Create the seed
const seed = bip39.mnemonicToSeed(mnemonic);

// Derived SeedValue from seed
seed.then(seedValue => {

    console.log("Seed Value : ", seedValue.toString("hex")); // Print Seed Value
    
    // Create Root through HD Key call function fromMasterSeed(seedvalue)
    const root = hdkey.fromMasterSeed(seedValue); 
    console.log("Root : ", root); // Print Root

    // Derived Master Private Key from Root
    const masterPrivateKey = root.privateKey.toString('hex');
    console.log("Master Private Key : ", masterPrivateKey); // Print Master Private Key

    // Derived Address Node from Root call function derive("m/44'/0'/0'/0/10")
    const addressNode = root.derive("m/44'/0'/0'/0/10");

    // Get Public and Private Keys from AddressNode
    const publicKey = addressNode.publicKey.toString('hex');
    const privateKey = addressNode.privateKey.toString('hex');

    // Print PublicKey and PrivateKey
    console.log('Derived Public Key : ', publicKey.toString('hex'));
    console.log('Derived Private Key : ', privateKey.toString('hex'));

    // Perform the Two Level Hashing..

    // 1. Hash the Public Key by SHA-256.
    const hashSHA256 = createHash('sha256').update(publicKey).digest();
    console.log("SHA-256 Hash Value : ", hashSHA256.toString('hex')); // Print hashSHA256
    
    // 2. Hash the hashSHA256 by RIPEMD-160
    const ripemd160 = createHash('ripemd160').update(hashSHA256).digest();
    console.log("RIPEMD-160 Hash Value : ", ripemd160.toString('hex'));

    // Concatnate the checkSum and ripemd160 
    const concatHash = Buffer.concat([checkSum, ripemd160]);

    // Encode the concatnated concatHash using Base58check to Bitcoin Address && Final Genrate BitCoin Address
    const bitcoinAddress = bs58check.encode(concatHash);
    console.log("Bitcoin Address : ", bitcoinAddress);

});
