const forge = require('node-forge');
const fs = require('fs-extra');
const _ = require('lodash');
const path = require('path');

forge.options.usePureJavaScript = true;

function getSerial() {
    return new Date().getTime().toString(); // Current time formatted in milliseconds since the epoch.
}

function listCerts(type, basePath = 'pki/') {
    const certs = [];

    if (basePath.substr(-1) !== '/') basePath += '/';

    if (fs.existsSync(basePath)) {
        const files = fs.readdirSync(basePath);

        _.forEach(files, (c, i) => {
            if(fs.lstatSync(basePath + c).isDirectory()){
                if (type !== 'ca') {
                    if (type === 'users') {
                        console.log('User certificates for ' + c + ':');
                    } else {
                        console.log('Server certificates for ' + c + ':');
                    }
                    const tempBase = basePath + c + '/' + type + '/';
                    if (fs.existsSync(tempBase)) {
                        const files = fs.readdirSync(tempBase);
                        _.forEach(files, c => {
                            certs.push(c);
                            console.log('\t' + c);
                        });
                    }
                } else {
                    if (i === 0) {
                        console.log('Available Certificate Authorities:');
                    }
                    certs.push(c);
                    console.log('\t' + c);
                }
            }
        });
    }

    return certs;
}

// Converts name to file path friendly name
function normalizeName(name) {
    return name.replace(/\s+/g, '-').toLowerCase();
}

function removeCerts(type, name, caName, basePath = 'pki/', callback = (err, data) => {}) {
    if (basePath.substr(-1) !== '/') basePath += '/';

    const certDir = path.join(basePath, normalizeName(caName), type, normalizeName(name));

    if (fs.existsSync(certDir)) {
        fs.removeSync(certDir);
        const success = {
            message: `${name} was removed from ${caName}.`,
        };
        console.log(success.message);
        callback(null, success);
    } else {
        const error = {
            message: `${name} does not exist for ${caName}.`,
        };
        console.error(error.message);
        callback(error);
    }
}

function setExpirationDate(cert, expired) {
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();

    // if expired, set cert to be valid starting 1 year before today
    // if not expired, set cert to be valid starting yesterday
    expired
        ? cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 1)
        : cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);

    // if expired, set cert to be valid until yesterday
    // if not expired, set cert to be valid until 1 year from today
    expired
        ? cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() - 1)
        : cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
}

function setValidFrom(cert, date) {}

function setValidTo(cert, date) {}

function createMessageDigest() {
    return forge.md.sha384.create();
}

/**
 * Generates a key pair based on CNSA 2.0 requirements
 * @param {String} keyType 'ec' (default) or 'rsa'
 * @param {Number} keySize RSA key size (default 4096, min 3072)
 * @note: ECC P-384 uses DSSSL for key generation and certificate operations (CNSA 2.0 compliant)
 */
function generateKeyPair(keyType = 'ec', keySize = null) {
    const pki = forge.pki;
    
    if (keyType === 'ec') {
        // CNSA 2.0: ECC P-384 (secp384r1) - use DSSSL for full support
        const dsssl = require('./dsssl');
        const keyResult = dsssl.generateECCKeyPair('secp384r1');
        
        // Return object compatible with existing code
        // Store PEM paths for DSSSL-based certificate operations
        return {
            privateKey: {
                _eccPemPath: keyResult.keyPath,
                _eccPrivateKeyPem: keyResult.privateKeyPem,
                _keyType: 'ec',
                _tmpDir: keyResult.tmpDir,
                _cleanup: keyResult.cleanup
            },
            publicKey: {
                _eccPemPath: keyResult.pubPath,
                _eccPublicKeyPem: keyResult.publicKeyPem,
                _keyType: 'ec',
                _tmpDir: keyResult.tmpDir
            }
        };
    } else if (keyType === 'rsa') {
        // CNSA 2.0: RSA minimum 3072, default 4096
        const size = keySize && keySize >= 3072 ? keySize : 4096;
        return pki.rsa.generateKeyPair(size);
    }
    throw new Error(`Unsupported key type: ${keyType}`);
}

/**
 * Updates the CA database (index.txt) for CRL/OCSP support
 */
function updateCaDatabase(caPath, cert, status = 'V') {
    const fs = require('fs-extra');
    const path = require('path');
    const dbPath = path.join(caPath, 'index.txt');
    
    // OpenSSL index.txt format:
    // status (V/R/E) \t expiry \t revocation_date \t serial \t filename \t subject
    // Format expiry as YYMMDDHHMMSSZ (OpenSSL format)
    const expiryDate = cert.validity.notAfter;
    const year = expiryDate.getUTCFullYear().toString().substr(2);
    const month = String(expiryDate.getUTCMonth() + 1).padStart(2, '0');
    const day = String(expiryDate.getUTCDate()).padStart(2, '0');
    const hour = String(expiryDate.getUTCHours()).padStart(2, '0');
    const minute = String(expiryDate.getUTCMinutes()).padStart(2, '0');
    const second = String(expiryDate.getUTCSeconds()).padStart(2, '0');
    const expiry = `${year}${month}${day}${hour}${minute}${second}Z`;
    const serial = cert.serialNumber;
    const subject = cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join('/');
    
    const line = `${status}\t${expiry}\t\t${serial}\tunknown\t/${subject}\n`;
    
    fs.ensureDirSync(caPath);
    fs.appendFileSync(dbPath, line);
}

module.exports = {
    createMessageDigest,
    getSerial,
    listCerts,
    normalizeName,
    removeCerts,
    setExpirationDate,
    generateKeyPair,
    updateCaDatabase
};
