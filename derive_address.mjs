import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

const suiPrivKey = 'suiprivkey1qqwedz4mtjeyzjgjgvr72mw3hu7hypttrej3nsjhr6r0c22tmnr3qvgfw74';

try {
    const decoded = decodeSuiPrivateKey(suiPrivKey);
    console.log('Decoded object keys:', Object.keys(decoded));
    // The keys are usually schema and secretKey, but let's check the output from previous attempt.
    // In @mysten/sui v2.x, schema might be a string like 'ED25519'
    
    const secretKey = decoded.secretKey;
    console.log('Secret Key Bytes:', secretKey);

    const keypair = Ed25519Keypair.fromSecretKey(secretKey);
    const address = keypair.toSuiAddress(); // Use toSuiAddress() directly on keypair or via publicKey
    console.log('Derived Address:', address);
} catch (error) {
    console.error('Error:', error);
}
