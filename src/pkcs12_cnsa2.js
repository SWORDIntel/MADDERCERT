/**
 * MADCert CNSA 2.0 PKCS#12 Utility
 * Implements manual ASN.1 assembly for AES-256-GCM encryption
 * OID: 2.16.840.1.101.3.4.1.46 (aes256-GCM)
 */

const forge = require('node-forge');
const asn1 = forge.asn1;
const pki = forge.pki;
const { execSync } = require('child_process');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');

// CNSA 2.0 OIDs
const OIDS = {
    pkcs12: '1.2.840.113549.1.12',
    pkcs12PbeIds: '1.2.840.113549.1.12.1',
    pbes2: '1.2.840.113549.1.5.13',
    pbkdf2: '1.2.840.113549.1.5.12',
    aes256GCM: '2.16.840.1.101.3.4.1.46',
    sha384: '2.16.840.1.101.3.4.2.2',
    data: '1.2.840.113549.1.7.1',
    encryptedData: '1.2.840.113549.1.7.6',
    keyBag: '1.2.840.113549.1.12.10.1.1',
    pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
    certBag: '1.2.840.113549.1.12.10.1.3',
    x509Certificate: '1.2.840.113549.1.12.10.1.3.1'
};

/**
 * Creates a CNSA 2.0 compliant PKCS#12 PFX structure
 * @param {Object} privateKey Private key object
 * @param {Array} certChain Array of certificate objects
 * @param {String} password Password for encryption
 * @param {Object} options Options (iteration count, salt size, etc)
 */
function toPkcs12Asn1(privateKey, certChain, password, options = {}) {
    const iterationCount = options.count || 100000;
    const saltSize = options.saltSize || 32;
    const salt = forge.random.getBytesSync(saltSize);

    // 1. Create SafeBags
    const bags = [];

    // 1.1 Private Key Bag (Encrypted with AES-256-GCM)
    // Handle both RSA and ECC keys (CNSA 2.0 defaults to ECC P-384)
    let pkcs8Der;
    
    // Check if ECC key (has _eccPemPath property)
    if (privateKey && privateKey._eccPemPath) {
        // ECC key - convert to PKCS#8 DER using DSSSL
        const dsssl = require('./dsssl');
        const { binary: openssl, env } = dsssl.getDSSSLConfig();
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-p12-ecc-'));
        const pkcs8Path = path.join(tmpDir, 'key.pkcs8');
        
        try {
            // Convert ECC key to PKCS#8 DER format
            execSync(`${openssl} pkcs8 -topk8 -nocrypt -in ${privateKey._eccPemPath} -outform DER -out ${pkcs8Path}`, { stdio: 'pipe', env: env });
            pkcs8Der = fs.readFileSync(pkcs8Path, 'binary');
            fs.removeSync(tmpDir);
        } catch (err) {
            if (fs.existsSync(tmpDir)) {
                fs.removeSync(tmpDir);
            }
            throw new Error(`Failed to convert ECC key to PKCS#8: ${err.message}`);
        }
    } else {
        // RSA key - use node-forge
        const privateKeyAsn1 = pki.privateKeyToAsn1(privateKey);
        const pkcs8Asn1 = pki.wrapRsaPrivateKey(privateKeyAsn1);
        pkcs8Der = asn1.toDer(pkcs8Asn1).getBytes();
    }
    
    const encryptedKeyBag = encryptSafeBag(
        OIDS.pkcs8ShroudedKeyBag,
        pkcs8Der,
        password,
        iterationCount,
        salt
    );
    bags.push(encryptedKeyBag);

    // 1.2 Certificate Bags
    certChain.forEach(cert => {
        const certDer = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
        const certBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.certBag).getBytes()),
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.x509Certificate).getBytes()),
                    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, certDer)
                    ])
                ])
            ])
        ]);
        bags.push(certBag);
    });

    // 2. Create AuthenticatedSafe
    const authSafe = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.data).getBytes()),
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, asn1.toDer(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, bags)).getBytes())
            ])
        ])
    ]);

    const authSafeDer = asn1.toDer(authSafe).getBytes();

    // 3. Create MacData using SHA-384 HMAC (CNSA 2.0 compliant)
    // PKCS#12 requires MacData for compatibility even with AEAD encryption
    // MacData provides additional integrity verification layer
    const includeMacData = options.includeMacData !== false; // Default: true
    let macData = null;
    
    if (includeMacData) {
        const macSalt = forge.random.getBytesSync(20); // Standard salt size
        const macIterations = 1; // Standard for MacData
        const macKeyBytes = forge.pkcs5.pbkdf2(password, macSalt, macIterations, 48, forge.md.sha384.create()); // 48 bytes for SHA-384
        const macKey = forge.util.createBuffer(macKeyBytes); // Convert to forge buffer
        const mac = forge.hmac.create();
        mac.start('sha384', macKey);
        mac.update(authSafeDer);
        const macValue = mac.digest().getBytes();
        
        // MacData structure per PKCS#12 RFC 7292:
        // MacData ::= SEQUENCE {
        //     mac         DigestInfo,
        //     macSalt     OCTET STRING,
        //     iterations  INTEGER DEFAULT 1
        // }
        macData = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // DigestInfo (AlgorithmIdentifier + digest)
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // AlgorithmIdentifier
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.sha384).getBytes()),
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
                ]),
                // Digest (OCTET STRING)
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, macValue)
            ]),
            // macSalt
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, macSalt),
            // iterations
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(macIterations).getBytes())
        ]);
    }

    // 4. Create PFX structure with optional MacData
    const pfxElements = [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, forge.util.hexToBytes('03')), // version 3
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.data).getBytes()),
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, authSafeDer)
            ])
        ])
    ];
    
    // Add MacData if included (CONTEXT_SPECIFIC 0)
    if (macData) {
        pfxElements.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [macData]));
    }
    
    const pfx = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, pfxElements);
    
    return pfx;
}

/**
 * Encrypts a SafeBag using PBES2 + AES-256-GCM (CNSA 2.0 compliant)
 */
function encryptSafeBag(bagOid, data, password, count, salt) {
    const iv = forge.random.getBytesSync(12); // GCM standard IV size
    
    // Derive key using PBKDF2 + SHA-384
    const key = forge.pkcs5.pbkdf2(
        password,
        salt,
        count,
        32, // 256-bit key
        forge.md.sha384.create()
    );

    // Encrypt with AES-256-GCM
    const cipher = forge.cipher.createCipher('AES-GCM', key);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(data));
    cipher.finish();
    const ciphertext = cipher.output.getBytes();
    const tag = cipher.mode.tag.getBytes();

    // Construct PBES2 Parameters
    // SEQUENCE {
    //   encryptionScheme SEQUENCE {
    //     OID 2.16.840.1.101.3.4.1.46 (aes256-GCM)
    //     GCMParameters SEQUENCE {
    //       nonce OCTET STRING (IV)
    //       tagSize INTEGER (16)
    //     }
    //   }
    //   keyDerivationFunc SEQUENCE {
    //     OID 1.2.840.113549.1.5.12 (PBKDF2)
    //     PBKDF2-params SEQUENCE {
    //       salt OCTET STRING
    //       iterationCount INTEGER
    //       prf AlgorithmIdentifier (SHA-384)
    //     }
    //   }
    // }
    
    const pbes2Params = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // Key Derivation Function
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.pbkdf2).getBytes()),
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, salt),
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(count).getBytes()),
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.sha384).getBytes()),
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
                ])
            ])
        ]),
        // Encryption Scheme
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.aes256GCM).getBytes()),
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, iv),
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(16).getBytes()) // 128-bit tag
            ])
        ])
    ]);

    // Encrypted SafeBag
    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(bagOid).getBytes()),
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.pbes2).getBytes()),
                pbes2Params,
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, ciphertext + tag)
            ])
        ])
    ]);
}

module.exports = {
    toPkcs12Asn1
};
