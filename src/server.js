const _ = require('lodash');
const forge = require('node-forge');
const fs = require('fs-extra');
const os = require('os');
const path = require('path');
const audit = require('./audit');
const pqc = require('./pqc');
const dsssl = require('./dsssl');

forge.options.usePureJavaScript = true;
const pki = forge.pki;
const asn1 = forge.asn1;

const subjectAttrs = require('./subjectAttributes');
const utils = require('./utils');
const normalizeName = utils.normalizeName;
const pkcs12_cnsa2 = require('./pkcs12_cnsa2');

const DNS_TYPE = 2;
const IP_TYPE = 7;

function buildServerCert(keys, caCertName, caCert, localhost, options) {
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = utils.getSerial();

    const attrs = subjectAttrs(options);

    // Set the default expiration, then override with valid-from and/or valid-to
    const expired = _.get(options, 'expired', false);
    utils.setExpirationDate(cert, expired);

    if (options.validFrom) {
        // Parse the validFrom from ISO 8601 format
        cert.validity.notBefore = new Date(options.validFrom);
    }

    if (options.validTo) {
        // Parse the validTo from ISO 8601 format
        cert.validity.notAfter = new Date(options.validTo);
    }

    cert.setSubject(attrs);
    cert.setIssuer(caCert.subject.attributes);

    const extensions = [
        {
            name: 'basicConstraints',
            cA: false,
        },
        {
            name: 'keyUsage',
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true,
        },
        {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true,
        },
        {
            name: 'subjectKeyIdentifier',
        },
        {
            name: 'authorityKeyIdentifier',
            keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes(),
        },
    ];

    const altNames = [];

    if (localhost) {
        altNames.push({
            type: DNS_TYPE,
            value: 'localhost',
        });
        altNames.push({
            type: IP_TYPE,
            ip: '127.0.0.1',
        });
    }

    if (options.subjectAltDnsNames) {
        options.subjectAltDnsNames.forEach(function(dnsName) {
            altNames.push({
                type: DNS_TYPE,
                value: dnsName,
            });
        });
    }

    if (options.subjectAltIpNames) {
        options.subjectAltIpNames.forEach(function(ipName) {
            altNames.push({
                type: IP_TYPE,
                ip: ipName,
            });
        });
    }

    if (altNames.length > 0) {
        extensions.push({
            name: 'subjectAltName',
            altNames: altNames,
        });
    }

    cert.setExtensions(extensions);

    return cert;
}

async function createServerCert(serverName, caCertName, localhost, options = {}, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }

    const basePath = _.get(options, 'basePath', 'pki/');
    const password = _.get(options, 'password', 'changeme');
    const rootCaName = _.get(options, 'rootCaName');

    const caPath = path.join(basePath, normalizeName(caCertName), '/ca/');
    const serverDir = path.join(basePath, normalizeName(caCertName), '/servers/', normalizeName(serverName));
    const serverCertPath = path.join(serverDir, '/crt.pem');
    const serverKeyPath = path.join(serverDir, '/key.pem');
    const serverP12Path = path.join(serverDir, '/bundle.p12');

    if (!fs.existsSync(caPath)) {
        const err = {
            message: `Certificate Authority ${caCertName} does not exist, aborting creation of new server certificate`,
        };
        console.error(err.message);
        if (callback) callback(err);
        return;
    }

    const expired = _.get(options, 'expired', false);

    if (
        !fs.existsSync(serverDir) ||
        !fs.existsSync(serverCertPath) ||
        !fs.existsSync(serverKeyPath) ||
        !fs.existsSync(serverP12Path)
    ) {
        const keyType = _.get(options, 'keyType', 'ec');
        const keySize = _.get(options, 'keySize', 4096);
        const usePqc = _.get(options, 'pqc', false);
        const keys = utils.generateKeyPair(keyType, keySize);

        let rootCaCert;
        if (rootCaName) {
            const rootCaPath = path.join(basePath, normalizeName(rootCaName), '/ca/');
            const rootCaCertPem = fs.readFileSync(path.join(rootCaPath, '/crt.pem'), 'utf8');
            rootCaCert = forge.pki.certificateFromPem(rootCaCertPem);
        }

        // Load CA certificate and key
        const caCertPem = fs.readFileSync(path.join(caPath, '/crt.pem'), 'utf8');
        const caCert = forge.pki.certificateFromPem(caCertPem);
        const caKeyPem = fs.readFileSync(path.join(caPath, '/key.pem'), 'utf8');
        
        // Check if CA key is ECC
        let isCAECC = false;
        let caKey;
        try {
            caKey = forge.pki.privateKeyFromPem(caKeyPem);
            isCAECC = !caKey.n; // ECC keys don't have modulus n
        } catch (e) {
            isCAECC = true;
        }

        fs.ensureDirSync(serverDir);

        // Check if server key is ECC
        const isECCKey = keys.privateKey && keys.privateKey._eccPemPath;
        
        let certPem;
        let cert;

        if (isECCKey) {
            // Use DSSSL for ECC certificate creation
            const attrs = subjectAttrs(options);
            const caKeyPath = path.join(caPath, '/key.pem');
            const caCertPath = path.join(caPath, '/crt.pem');
            
            // Create server certificate signed by CA via DSSSL
            certPem = dsssl.createECCCertificate(
                keys.privateKey._eccPemPath,
                attrs,
                caKeyPath,
                caCertPath,
                {
                    serialNumber: utils.getSerial(),
                    validFrom: options.validFrom,
                    validTo: options.validTo,
                    expired: expired
                }
            );
            
            // Parse certificate for P12 and PQC operations
            cert = pki.certificateFromPem(certPem);
            
            // Write key PEM
            fs.writeFileSync(serverKeyPath, keys.privateKey._eccPrivateKeyPem);
        } else {
            // RSA key - use node-forge (existing flow)
            cert = buildServerCert(
                keys,
                caCertName,
                caCert,
                localhost,
                options
            );
            cert.sign(caKey, utils.createMessageDigest());
            
            const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
            fs.outputFileSync(serverKeyPath, privateKeyPem);
        }

        // Hybrid PQC signing (works for both ECC and RSA)
        if (usePqc) {
            const pqcKeys = await pqc.generateMLDSA87KeyPair();
            const caPqcKeyPath = path.join(caPath, '/pqc_private.bin');
            const certAsn1 = pki.certificateToAsn1(cert);
            
            if (fs.existsSync(caPqcKeyPath)) {
                const caPqcKey = fs.readFileSync(caPqcKeyPath);
                const tbsCertDer = asn1.toDer(certAsn1.value[0]).getBytes();
                const pqcSignature = await pqc.signMLDSA87(Buffer.from(tbsCertDer, 'binary'), new Uint8Array(caPqcKey));
                pqc.addHybridSignatureExtension(certAsn1, pqcSignature, pqc.OIDS.mlDsa87);
                certPem = pki.certificateToPem(pki.certificateFromAsn1(certAsn1));
            }

            fs.outputFileSync(path.join(serverDir, '/pqc_public.bin'), Buffer.from(pqcKeys.publicKey));
            fs.outputFileSync(path.join(serverDir, '/pqc_private.bin'), Buffer.from(pqcKeys.privateKey));
        } else if (!isECCKey) {
            // Convert RSA certificate to PEM
            certPem = pki.certificateToPem(cert);
        }

        fs.outputFileSync(serverCertPath, certPem);

        let p12Asn1;
        //create .p12 file (CNSA 2.0 compliant: AES-256-GCM + PBKDF2-SHA384)
        if (rootCaCert) {
            p12Asn1 = pkcs12_cnsa2.toPkcs12Asn1(
                keys.privateKey,
                [cert, caCert, rootCaCert],
                password,
                options
            );
        } else {
            p12Asn1 = pkcs12_cnsa2.toPkcs12Asn1(
                keys.privateKey,
                [cert, caCert],
                password,
                options
            );
        }
        const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
        fs.writeFileSync(serverP12Path, p12Der, {
            encoding: 'binary',
        });

        audit.auditLog(audit.AUDIT_EVENTS.CERT_CREATED, {
            type: 'server',
            name: serverName,
            caName: caCertName,
            serialNumber: cert.serialNumber,
            subject: cert.subject.attributes,
            keyType: keyType,
            keySize: keyType === 'rsa' ? keySize : 384,
            encryption: 'AES-256-GCM',
            kdf: 'PBKDF2-SHA384',
            pqc: usePqc ? 'ML-DSA-87' : 'none'
        }, basePath);

        const success = {
            message: `${serverName} ${
                expired ? 'expired ' : ''
            }server certificate was created and signed by ${caCertName}.`,
        };
        console.log(success.message);
        if (callback) callback(null, success);
    } else {
        const err = {
            message: `${serverName} ${
                expired ? 'expired ' : ''
            }server certificate already exists in ${caCertName}.`,
        };
        console.error(err.message);
        if (callback) callback(err);
    }
}

function listServerCerts(path) {
    utils.listCerts('servers', path);
}

function removeServerCert(name, caName, basePath = 'pki/', callback) {
    audit.auditLog(audit.AUDIT_EVENTS.CERT_REMOVED, {
        type: 'server',
        name: name,
        caName: caName
    }, basePath);
    utils.removeCerts('servers', name, caName, basePath, callback);
}

module.exports = {
    createServerCert,
    listServerCerts,
    removeServerCert,
};
