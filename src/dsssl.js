/**
 * MADCert DSSSL Integration Module
 * Provides ECC P-384 certificate operations using DSSSL (DSMIL-Grade OpenSSL)
 * CNSA 2.0 Compliant
 */

const { execSync } = require('child_process');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const forge = require('node-forge');
const pki = forge.pki;

/**
 * Gets the DSSSL openssl binary path and environment
 * Falls back to system openssl if DSSSL not found
 */
function getDSSSLConfig() {
    // Try DSSSL first (preferred for CNSA 2.0 PQC and ECC support)
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
 * Generates an ECC P-384 key pair using DSSSL
 * @param {String} curve Curve name (default: secp384r1 for CNSA 2.0)
 * @returns {Object} Object with privateKeyPem and publicKeyPem paths, and cleanup function
 */
function generateECCKeyPair(curve = 'secp384r1') {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-ecc-'));
    const keyPath = path.join(tmpDir, 'key.pem');
    const pubPath = path.join(tmpDir, 'pub.pem');
    const { binary: openssl, env } = getDSSSLConfig();

    try {
        // Generate ECC private key
        execSync(`${openssl} ecparam -genkey -name ${curve} -out ${keyPath}`, { stdio: 'pipe', env: env });
        // Extract public key
        execSync(`${openssl} ec -in ${keyPath} -pubout -out ${pubPath}`, { stdio: 'pipe', env: env });

        const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
        const publicKeyPem = fs.readFileSync(pubPath, 'utf8');

        return {
            privateKeyPem: privateKeyPem,
            publicKeyPem: publicKeyPem,
            keyPath: keyPath,
            pubPath: pubPath,
            tmpDir: tmpDir,
            cleanup: () => {
                if (fs.existsSync(tmpDir)) {
                    fs.removeSync(tmpDir);
                }
            }
        };
    } catch (err) {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
        throw new Error(`ECC ${curve} key generation failed: ${err.message}`);
    }
}

/**
 * Creates a certificate signing request (CSR) for ECC key
 * @param {String} keyPath Path to private key PEM file
 * @param {Array} subjectAttrs Array of subject attributes [{name: 'CN', value: 'example.com'}, ...]
 * @param {Object} options Additional options (extensions, etc.)
 * @returns {String} Path to CSR file
 */
function createECCCSR(keyPath, subjectAttrs, options = {}) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-csr-'));
    const csrPath = path.join(tmpDir, 'csr.pem');
    const configPath = path.join(tmpDir, 'openssl.cnf');
    const { binary: openssl, env } = getDSSSLConfig();

    try {
        // Build subject string from attributes
        const subjectParts = subjectAttrs.map(attr => {
            const name = attr.shortName || attr.name;
            return `/${name}=${attr.value}`;
        }).join('');
        const subject = subjectParts || '/CN=Default';

        // Create minimal OpenSSL config for CSR
        const configContent = `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
${subjectAttrs.map(attr => {
    const name = (attr.shortName || attr.name).toUpperCase();
    return `${name} = ${attr.value}`;
}).join('\n')}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
`;

        fs.writeFileSync(configPath, configContent);

        // Generate CSR
        execSync(`${openssl} req -new -key ${keyPath} -out ${csrPath} -config ${configPath}`, { stdio: 'pipe', env: env });

        return {
            csrPath: csrPath,
            tmpDir: tmpDir,
            cleanup: () => {
                if (fs.existsSync(tmpDir)) {
                    fs.removeSync(tmpDir);
                }
            }
        };
    } catch (err) {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
        throw new Error(`ECC CSR creation failed: ${err.message}`);
    }
}

/**
 * Creates and signs an ECC certificate using DSSSL
 * @param {String} keyPath Path to ECC private key PEM file
 * @param {Array} subjectAttrs Subject attributes
 * @param {String} caKeyPath Path to CA private key PEM file
 * @param {String} caCertPath Path to CA certificate PEM file
 * @param {Object} options Certificate options (serial, validity, extensions, etc.)
 * @returns {String} Certificate PEM content
 */
function createECCCertificate(keyPath, subjectAttrs, caKeyPath, caCertPath, options = {}) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-cert-'));
    const csrPath = path.join(tmpDir, 'csr.pem');
    const certPath = path.join(tmpDir, 'cert.pem');
    const configPath = path.join(tmpDir, 'openssl.cnf');
    const { binary: openssl, env } = getDSSSLConfig();

    try {
        // Create CSR first
        const csrResult = createECCCSR(keyPath, subjectAttrs, options);
        fs.copyFileSync(csrResult.csrPath, csrPath);
        csrResult.cleanup();

        // Calculate validity dates
        const notBefore = options.validFrom ? new Date(options.validFrom) : new Date();
        const notAfter = options.validTo ? new Date(options.validTo) : new Date();
        notAfter.setFullYear(notAfter.getFullYear() + (options.expired ? -1 : 1));

        // Format dates for OpenSSL (YYYYMMDDHHMMSSZ)
        const formatDate = (date) => {
            const year = date.getUTCFullYear();
            const month = String(date.getUTCMonth() + 1).padStart(2, '0');
            const day = String(date.getUTCDate()).padStart(2, '0');
            const hour = String(date.getUTCHours()).padStart(2, '0');
            const minute = String(date.getUTCMinutes()).padStart(2, '0');
            const second = String(date.getUTCSeconds()).padStart(2, '0');
            return `${year}${month}${day}${hour}${minute}${second}Z`;
        };

        const serial = options.serialNumber || Date.now().toString();

        // Sign certificate using DSSSL
        // Use SHA-384 for CNSA 2.0 compliance
        execSync(
            `${openssl} x509 -req -in ${csrPath} -CA ${caCertPath} -CAkey ${caKeyPath} ` +
            `-out ${certPath} -sha384 -days ${Math.floor((notAfter - notBefore) / (1000 * 60 * 60 * 24))} ` +
            `-set_serial ${serial} -notBefore ${formatDate(notBefore)} -notAfter ${formatDate(notAfter)}`,
            { stdio: 'pipe', env: env }
        );

        const certPem = fs.readFileSync(certPath, 'utf8');

        // Cleanup
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }

        return certPem;
    } catch (err) {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
        throw new Error(`ECC certificate creation failed: ${err.message}`);
    }
}

/**
 * Creates a self-signed ECC certificate (for CA certificates)
 * @param {String} keyPath Path to ECC private key PEM file
 * @param {Array} subjectAttrs Subject attributes
 * @param {Object} options Certificate options
 * @returns {String} Certificate PEM content
 */
function createECCSelfSignedCertificate(keyPath, subjectAttrs, options = {}) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'madcert-ca-'));
    const certPath = path.join(tmpDir, 'cert.pem');
    const configPath = path.join(tmpDir, 'openssl.cnf');
    const { binary: openssl, env } = getDSSSLConfig();

    try {
        // Build subject string
        const subjectParts = subjectAttrs.map(attr => {
            const name = attr.shortName || attr.name;
            return `/${name}=${attr.value}`;
        }).join('');
        const subject = subjectParts || '/CN=Default CA';

        // Calculate validity dates
        const notBefore = options.validFrom ? new Date(options.validFrom) : new Date();
        const notAfter = options.validTo ? new Date(options.validTo) : new Date();
        notAfter.setFullYear(notAfter.getFullYear() + (options.expired ? -1 : 1));

        const formatDate = (date) => {
            const year = date.getUTCFullYear();
            const month = String(date.getUTCMonth() + 1).padStart(2, '0');
            const day = String(date.getUTCDate()).padStart(2, '0');
            const hour = String(date.getUTCHours()).padStart(2, '0');
            const minute = String(date.getUTCMinutes()).padStart(2, '0');
            const second = String(date.getUTCSeconds()).padStart(2, '0');
            return `${year}${month}${day}${hour}${minute}${second}Z`;
        };

        const serial = options.serialNumber || Date.now().toString();
        const days = Math.floor((notAfter - notBefore) / (1000 * 60 * 60 * 24));

        // Create self-signed certificate using DSSSL
        // Use SHA-384 for CNSA 2.0 compliance
        execSync(
            `${openssl} req -new -x509 -key ${keyPath} -out ${certPath} -sha384 ` +
            `-days ${days} -subj "${subject}" ` +
            `-set_serial ${serial} -notBefore ${formatDate(notBefore)} -notAfter ${formatDate(notAfter)}`,
            { stdio: 'pipe', env: env }
        );

        const certPem = fs.readFileSync(certPath, 'utf8');

        // Cleanup
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }

        return certPem;
    } catch (err) {
        if (fs.existsSync(tmpDir)) {
            fs.removeSync(tmpDir);
        }
        throw new Error(`ECC self-signed certificate creation failed: ${err.message}`);
    }
}

module.exports = {
    getDSSSLConfig,
    generateECCKeyPair,
    createECCCSR,
    createECCCertificate,
    createECCSelfSignedCertificate
};
