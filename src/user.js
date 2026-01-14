const _ = require('lodash');
const forge = require('node-forge');
const fs = require('fs-extra');
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

function buildUserCert(keys, options, caCert) {
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

    if (options.subjectAltEmailNames) {
        options.subjectAltEmailNames.forEach(function(email) {
            extensions.push({
                name: 'subjectAltName',
                altNames: [
                    {
                        type: 1, // rfc822Name
                        value: email,
                    },
                ],
            });
        });
    }

    cert.setExtensions(extensions);

    return cert;
}

async function createUserCert(userName, caCertName, options = {}, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }

    const basePath = _.get(options, 'basePath', 'pki/');
    const password = _.get(options, 'password', 'changeme');
    const rootCaName = _.get(options, 'rootCaName');

    const caPath = basePath + normalizeName(caCertName) + '/ca/';
    const userDir = basePath + normalizeName(caCertName) + '/users/' + normalizeName(userName);
    const userCertPath = userDir + '/crt.pem';
    const userKeyPath = userDir + '/key.pem';
    const userP12Path = userDir + '/bundle.p12';

    if (!fs.existsSync(caPath)) {
        const err = {
            message: `Certificate Authority ${caCertName} does not exist, aborting creation of new user certificate`,
        };
        console.error(err.message);
        if (callback) callback(err);
        return;
    }

    const expired = _.get(options, 'expired', false);

    if (
        !fs.existsSync(userDir) ||
        !fs.existsSync(userCertPath) ||
        !fs.existsSync(userKeyPath) ||
        !fs.existsSync(userP12Path)
    ) {
        const keyType = _.get(options, 'keyType', 'ec');
        const keySize = _.get(options, 'keySize', 4096);
        const usePqc = _.get(options, 'pqc', false);
        const keys = utils.generateKeyPair(keyType, keySize);

        let rootCaCert;
        if (rootCaName) {
            const rootCaPath = basePath + normalizeName(rootCaName) + '/ca/';
            const rootCaCertPem = fs.readFileSync(rootCaPath + '/crt.pem', 'utf8');
            rootCaCert = forge.pki.certificateFromPem(rootCaCertPem);
        }

        // Load CA certificate and key
        const caCertPem = fs.readFileSync(caPath + '/crt.pem', 'utf8');
        const caCert = forge.pki.certificateFromPem(caCertPem);
        const caKeyPem = fs.readFileSync(caPath + '/key.pem', 'utf8');
        
        // Check if CA key is ECC
        let isCAECC = false;
        let caKey;
        try {
            caKey = forge.pki.privateKeyFromPem(caKeyPem);
            isCAECC = !caKey.n; // ECC keys don't have modulus n
        } catch (e) {
            isCAECC = true;
        }

        // Check if user key is ECC
        const isECCKey = keys.privateKey && keys.privateKey._eccPemPath;
        
        let certPem;
        let cert;

        if (isECCKey) {
            // Use DSSSL for ECC certificate creation
            const attrs = subjectAttrs(options);
            const caKeyPath = caPath + '/key.pem';
            const caCertPath = caPath + '/crt.pem';
            
            // Create user certificate signed by CA via DSSSL
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
            fs.writeFileSync(userKeyPath, keys.privateKey._eccPrivateKeyPem);
        } else {
            // RSA key - use node-forge (existing flow)
            cert = buildUserCert(keys, options, caCert);
            cert.sign(caKey, utils.createMessageDigest());
            
            const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
            fs.outputFileSync(userKeyPath, privateKeyPem);
        }

        // Hybrid PQC signing (works for both ECC and RSA)
        if (usePqc) {
            const pqcKeys = await pqc.generateMLDSA87KeyPair();
            const caPqcKeyPath = caPath + '/pqc_private.bin';
            const certAsn1 = pki.certificateToAsn1(cert);
            
            if (fs.existsSync(caPqcKeyPath)) {
                const caPqcKey = fs.readFileSync(caPqcKeyPath);
                const tbsCertDer = asn1.toDer(certAsn1.value[0]).getBytes();
                const pqcSignature = await pqc.signMLDSA87(Buffer.from(tbsCertDer, 'binary'), new Uint8Array(caPqcKey));
                pqc.addHybridSignatureExtension(certAsn1, pqcSignature, pqc.OIDS.mlDsa87);
                certPem = pki.certificateToPem(pki.certificateFromAsn1(certAsn1));
            }

            fs.outputFileSync(userDir + '/pqc_public.bin', Buffer.from(pqcKeys.publicKey));
            fs.outputFileSync(userDir + '/pqc_private.bin', Buffer.from(pqcKeys.privateKey));
        } else if (!isECCKey) {
            // Convert RSA certificate to PEM
            certPem = pki.certificateToPem(cert);
        }

        fs.outputFileSync(userCertPath, certPem);

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
        fs.writeFileSync(userP12Path, p12Der, {
            encoding: 'binary',
        });

        audit.auditLog(audit.AUDIT_EVENTS.CERT_CREATED, {
            type: 'user',
            name: userName,
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
            message: `${userName} ${
                expired ? 'expired ' : ''
            }user certificate was created and signed by ${caCertName}.`,
        };

        console.log(success.message);
        if (callback) callback(null, success);
    } else {
        const err = {
            message: `${userName} ${
                expired ? 'expired ' : ''
            }user certificate already exists in ${caCertName}.`,
        };
        console.error(err.message);
        if (callback) callback(err);
    }
}

function listUserCerts(path) {
    return utils.listCerts('users', path);
}

function removeUserCert(name, caName, basePath = 'pki/', callback) {
    audit.auditLog(audit.AUDIT_EVENTS.CERT_REMOVED, {
        type: 'user',
        name: name,
        caName: caName
    }, basePath);
    utils.removeCerts('users', name, caName, basePath, callback);
}

module.exports = {
    createUserCert,
    listUserCerts,
    removeUserCert,
};
