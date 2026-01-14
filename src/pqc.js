/**
 * MADCert Post-Quantum Cryptography Module
 * Uses DSSSL (DSMIL-Grade OpenSSL) for ML-KEM-1024 and ML-DSA-87 support
 * CNSA 2.0 Compliant
 */

const { execSync } = require('child_process');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const forge = require('node-forge');
const asn1 = forge.asn1;

// PQC OIDs
const OIDS = {
    mlKem1024: '2.16.840.1.101.3.4.4.3',
    mlDsa87: '2.16.840.1.101.3.4.3.19',
    altSignatureAlgorithm: '2.5.29.72',
    altSignatureValue: '2.5.29.73',
    altPublicKey: '2.5.29.74'
};

/**
 * Gets the DSSSL openssl binary path and environment
 * Falls back to system openssl if DSSSL not found
 */
function getOpenSSLConfig() {
    // Try DSSSL first (preferred for CNSA 2.0 PQC support)
    const dssslBase = path.join(__dirname, '../../..', 'toolchains/DSSSL');
    const dssslBin = path.join(dssslBase, 'apps/openssl');
    const dssslLib = path.join(dssslBase);
    
    if (fs.existsSync(dssslBin)) {
        // Set LD_LIBRARY_PATH to include DSSSL libraries
        const env = Object.assign({}, process.env);
        const existingLibPath = env.LD_LIBRARY_PATH || '';
        env.LD_LIBRARY_PATH = dssslLib + (existingLibPath ? ':' + existingLibPath : '');
        return { binary: dssslBin, env: env };
    }
    // Fallback to system openssl
    return { binary: 'openssl', env: process.env };
}

/**
 * Generates an ML-KEM-1024 key pair using DSSSL (or system OpenSSL)
 */
async function generateMLKEM1024KeyPair() {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-pqc-'));
    const privPath = path.join(tmpDir, 'priv.pem');
    const pubPath = path.join(tmpDir, 'pub.pem');
    const { binary: openssl, env } = getOpenSSLConfig();

    try {
        // DSSSL uses MLKEM1024 (no hyphen), system OpenSSL may use ML-KEM-1024
        // Try DSSSL format first, fallback to system format
        try {
            execSync(`${openssl} genpkey -algorithm MLKEM1024 -out ${privPath}`, { stdio: 'pipe', env: env });
        } catch (e) {
            execSync(`${openssl} genpkey -algorithm ML-KEM-1024 -out ${privPath}`, { stdio: 'pipe', env: env });
        }
        execSync(`${openssl} pkey -in ${privPath} -pubout -out ${pubPath}`, { stdio: 'pipe', env: env });

        const privateKey = fs.readFileSync(privPath);
        const publicKey = fs.readFileSync(pubPath);

        return {
            publicKey: publicKey,
            privateKey: privateKey,
            algorithm: 'ML-KEM-1024',
            oid: OIDS.mlKem1024
        };
    } catch (err) {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
        throw new Error(`ML-KEM-1024 key generation failed: ${err.message}`);
    } finally {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
    }
}

/**
 * Generates an ML-DSA-87 key pair using DSSSL (or system OpenSSL)
 */
async function generateMLDSA87KeyPair() {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-pqc-'));
    const privPath = path.join(tmpDir, 'priv.pem');
    const pubPath = path.join(tmpDir, 'pub.pem');
    const { binary: openssl, env } = getOpenSSLConfig();

    try {
        // DSSSL uses MLDSA87 (no hyphen), system OpenSSL may use ML-DSA-87
        // Try DSSSL format first, fallback to system format
        try {
            execSync(`${openssl} genpkey -algorithm MLDSA87 -out ${privPath}`, { stdio: 'pipe', env: env });
        } catch (e) {
            execSync(`${openssl} genpkey -algorithm ML-DSA-87 -out ${privPath}`, { stdio: 'pipe', env: env });
        }
        execSync(`${openssl} pkey -in ${privPath} -pubout -out ${pubPath}`, { stdio: 'pipe', env: env });

        const privateKey = fs.readFileSync(privPath);
        const publicKey = fs.readFileSync(pubPath);

        return {
            publicKey: publicKey,
            privateKey: privateKey,
            algorithm: 'ML-DSA-87',
            oid: OIDS.mlDsa87
        };
    } catch (err) {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
        throw new Error(`ML-DSA-87 key generation failed: ${err.message}`);
    } finally {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
    }
}

/**
 * Signs data using ML-DSA-87 via DSSSL (or system OpenSSL)
 */
async function signMLDSA87(data, privateKey) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-sign-'));
    const dataPath = path.join(tmpDir, 'data.bin');
    const privPath = path.join(tmpDir, 'priv.pem');
    const sigPath = path.join(tmpDir, 'sig.bin');
    const { binary: openssl, env } = getOpenSSLConfig();

    try {
        fs.writeFileSync(dataPath, data);
        fs.writeFileSync(privPath, privateKey);

        execSync(`${openssl} pkeyutl -sign -in ${dataPath} -inkey ${privPath} -out ${sigPath}`, { stdio: 'pipe', env: env });
        return fs.readFileSync(sigPath);
    } catch (err) {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
        throw new Error(`ML-DSA-87 signing failed: ${err.message}`);
    } finally {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
    }
}

/**
 * Verifies ML-DSA-87 signature via DSSSL (or system OpenSSL)
 */
async function verifyMLDSA87(data, signature, publicKey) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-verify-'));
    const dataPath = path.join(tmpDir, 'data.bin');
    const pubPath = path.join(tmpDir, 'pub.pem');
    const sigPath = path.join(tmpDir, 'sig.bin');
    const { binary: openssl, env } = getOpenSSLConfig();

    try {
        fs.writeFileSync(dataPath, data);
        fs.writeFileSync(pubPath, publicKey);
        fs.writeFileSync(sigPath, signature);

        execSync(`${openssl} pkeyutl -verify -in ${dataPath} -sigfile ${sigPath} -pubin -inkey ${pubPath}`, { stdio: 'pipe', env: env });
        return true;
    } catch (e) {
        return false;
    } finally {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
    }
}

/**
 * Adds a PQC signature as a hybrid/dual signature extension to an ASN.1 certificate
 */
function addHybridSignatureExtension(certAsn1, pqcSignature, pqcAlgorithmOid) {
    const tbsCert = certAsn1.value[0];
    let extensions;
    
    for (let i = 0; i < tbsCert.value.length; i++) {
        const item = tbsCert.value[i];
        if (item.tagClass === asn1.Class.CONTEXT_SPECIFIC && item.type === 3) {
            extensions = item.value[0];
            break;
        }
    }

    if (!extensions) {
        extensions = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
        tbsCert.value.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 3, true, [extensions]));
    }

    // Add id-ce-altSignatureAlgorithm (2.5.29.72)
    extensions.value.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.altSignatureAlgorithm).getBytes()),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(pqcAlgorithmOid).getBytes())
        ])
    ]));

    // Add id-ce-altSignatureValue (2.5.29.73)
    extensions.value.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OIDS.altSignatureValue).getBytes()),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, forge.util.binary.raw.encode(pqcSignature))
    ]));
}

module.exports = {
    generateMLKEM1024KeyPair,
    generateMLDSA87KeyPair,
    signMLDSA87,
    verifyMLDSA87,
    addHybridSignatureExtension,
    OIDS
};
