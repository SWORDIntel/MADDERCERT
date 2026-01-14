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

function buildCACert(keys, options, caCert = null) {
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
    const caSubject = _.get(caCert, "subject.attributes", null);
    cert.setSubject(attrs);
    cert.setIssuer(caSubject ? caSubject : attrs);
    const extensions = [
        {
            name: 'basicConstraints',
            cA: true,
            critical: true,
        },
        {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            critical: true,
            cRLSign: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        },
        {
            name: 'subjectKeyIdentifier',
        },
    ];

    if(caCert){
        extensions.push({
            name: 'authorityKeyIdentifier',
            keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes(),
        });
        extensions.push(
        {
            name: 'extKeyUsage',
            serverAuth: true,
            critical: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true
        });
    }

    cert.setExtensions(extensions);

    return cert;
}

async function createCACert(caName, options = {}) {
    let basePath = _.get(options, 'basePath', 'pki/');
    if (basePath.substr(-1) !== '/') basePath += '/';

    if (options.validFrom && options.validTo) {
        const validFrom = new Date(options.validFrom);
        const validTo = new Date(options.validTo);
        if (validTo.getTime() < validFrom.getTime()) {
            console.log(
                `Expiration date ${options.validTo} before start date ${options.validFrom}, aborting creation of new CA certificate`
            );
            return;
        }
    }

    const caPath = basePath + normalizeName(caName) + '/ca/';
    if (!fs.existsSync(caPath)) {
        const keyType = _.get(options, 'keyType', 'ec');
        const keySize = _.get(options, 'keySize', 4096);
        const usePqc = _.get(options, 'pqc', false);
        const keys = utils.generateKeyPair(keyType, keySize);
        
        fs.ensureDirSync(caPath);

        // Check if ECC key (has _eccPemPath property)
        const isECCKey = keys.privateKey && keys.privateKey._eccPemPath;
        
        let certPem;
        let certSerial;
        let certSubject;

        if (isECCKey) {
            // Use DSSSL for ECC certificate creation
            const attrs = subjectAttrs(options);
            const serial = utils.getSerial();
            
            // Create self-signed ECC certificate via DSSSL
            certPem = dsssl.createECCSelfSignedCertificate(
                keys.privateKey._eccPemPath,
                attrs,
                {
                    serialNumber: serial,
                    validFrom: options.validFrom,
                    validTo: options.validTo,
                    expired: options.expired
                }
            );
            
            // Parse certificate to get serial and subject for audit
            const cert = pki.certificateFromPem(certPem);
            certSerial = cert.serialNumber;
            certSubject = cert.subject.attributes;
            
            // Write key PEM (already in PEM format from DSSSL)
            fs.writeFileSync(caPath + '/' + 'key.pem', keys.privateKey._eccPrivateKeyPem);
            
            // Hybrid PQC signing for ECC certificate
            if (usePqc) {
                const pqcKeys = await pqc.generateMLDSA87KeyPair();
                const certAsn1 = pki.certificateToAsn1(cert);
                const tbsCertDer = asn1.toDer(certAsn1.value[0]).getBytes();
                const pqcSignature = await pqc.signMLDSA87(Buffer.from(tbsCertDer, 'binary'), pqcKeys.privateKey);
                pqc.addHybridSignatureExtension(certAsn1, pqcSignature, pqc.OIDS.mlDsa87);
                
                // Write out PQC keys
                fs.outputFileSync(caPath + '/pqc_public.bin', Buffer.from(pqcKeys.publicKey));
                fs.outputFileSync(caPath + '/pqc_private.bin', Buffer.from(pqcKeys.privateKey));
                
                certPem = pki.certificateToPem(pki.certificateFromAsn1(certAsn1));
            }
        } else {
            // RSA key - use node-forge (existing flow)
            const cert = buildCACert(keys, options);
            cert.sign(keys.privateKey, utils.createMessageDigest());
            
            certSerial = cert.serialNumber;
            certSubject = cert.subject.attributes;

            // Hybrid PQC signing
            if (usePqc) {
                const pqcKeys = await pqc.generateMLDSA87KeyPair();
                const certAsn1 = pki.certificateToAsn1(cert);
                const tbsCertDer = asn1.toDer(certAsn1.value[0]).getBytes();
                const pqcSignature = await pqc.signMLDSA87(Buffer.from(tbsCertDer, 'binary'), pqcKeys.privateKey);
                pqc.addHybridSignatureExtension(certAsn1, pqcSignature, pqc.OIDS.mlDsa87);
                
                // Write out PQC keys
                fs.outputFileSync(caPath + '/pqc_public.bin', Buffer.from(pqcKeys.publicKey));
                fs.outputFileSync(caPath + '/pqc_private.bin', Buffer.from(pqcKeys.privateKey));
                
                certPem = pki.certificateToPem(pki.certificateFromAsn1(certAsn1));
            } else {
                certPem = pki.certificateToPem(cert);
            }

            const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
            fs.outputFileSync(caPath + '/' + 'key.pem', privateKeyPem);
        }

        // Write certificate and serial
        fs.outputFileSync(caPath + '/' + 'crt.pem', certPem);
        fs.outputFileSync(caPath + '/' + 'serial.txt', '01');

        // Cleanup ECC temporary directory if needed
        if (isECCKey && keys.privateKey._cleanup) {
            // Keep key files but cleanup temp directory structure
            // Key PEMs are already written to caPath
        }

        audit.auditLog(audit.AUDIT_EVENTS.CA_CREATED, {
            caName: caName,
            subject: certSubject,
            serialNumber: certSerial,
            keyType: keyType,
            keySize: keyType === 'rsa' ? keySize : 384,
            pqc: usePqc ? 'ML-DSA-87' : 'none'
        }, basePath);

        console.log('Certificate authority ' + caName + ' was created.');
    } else {
        console.log('Certificate authority ' + caName + ' already exists.');
    }
}

async function createIntermediateCACert(caName, rootCaName, options = {}) {
    let basePath = _.get(options, 'basePath', 'pki/');
    if (basePath.substr(-1) !== '/') basePath += '/';

    if (options.validFrom && options.validTo) {
        const validFrom = new Date(options.validFrom);
        const validTo = new Date(options.validTo);
        if (validTo.getTime() < validFrom.getTime()) {
            console.log(
                `Expiration date ${options.validTo} before start date ${options.validFrom}, aborting creation of new intermediate CA certificate`
            );
            return;
        }
    }

    const newCaPath = basePath + normalizeName(caName) + '/ca/';
    const rootCaPath = basePath + normalizeName(rootCaName) + '/ca/';

    if (!fs.existsSync(rootCaPath)) {
        console.log(
            `Certificate Authority ${rootCaName} does not exist, aborting creation of new intermediate CA certificate`
        );
        return;
    }

    if (!fs.existsSync(newCaPath)) {
        // Load root CA certificate and key
        const rootCaCertPem = fs.readFileSync(rootCaPath + '/crt.pem', 'utf8');
        const caCert = forge.pki.certificateFromPem(rootCaCertPem);
        const rootCaKeyPem = fs.readFileSync(rootCaPath + '/key.pem', 'utf8');
        
        // Check if root CA key is ECC (try to parse, if fails assume RSA)
        let isRootCAECC = false;
        let caKey;
        try {
            caKey = forge.pki.privateKeyFromPem(rootCaKeyPem);
            isRootCAECC = !caKey.n; // ECC keys don't have modulus n
        } catch (e) {
            // If parsing fails, might be ECC - will handle via DSSSL
            isRootCAECC = true;
        }

        const keyType = _.get(options, 'keyType', 'ec');
        const keySize = _.get(options, 'keySize', 4096);
        const usePqc = _.get(options, 'pqc', false);
        const keys = utils.generateKeyPair(keyType, keySize);
        
        fs.ensureDirSync(newCaPath);

        // Check if new intermediate CA key is ECC
        const isECCKey = keys.privateKey && keys.privateKey._eccPemPath;
        
        let certPem;
        let certSerial;
        let certSubject;

        if (isECCKey) {
            // Use DSSSL for ECC certificate creation
            const attrs = subjectAttrs(options);
            const serial = utils.getSerial();
            
            // Determine CA key path (ECC or RSA)
            const caKeyPath = isRootCAECC ? rootCaPath + '/key.pem' : rootCaPath + '/key.pem';
            const caCertPath = rootCaPath + '/crt.pem';
            
            // Create intermediate CA certificate signed by root CA via DSSSL
            certPem = dsssl.createECCCertificate(
                keys.privateKey._eccPemPath,
                attrs,
                caKeyPath,
                caCertPath,
                {
                    serialNumber: serial,
                    validFrom: options.validFrom,
                    validTo: options.validTo,
                    expired: options.expired
                }
            );
            
            // Parse certificate to get serial and subject for audit
            const cert = pki.certificateFromPem(certPem);
            certSerial = cert.serialNumber;
            certSubject = cert.subject.attributes;
            
            // Write key PEM
            fs.writeFileSync(newCaPath + '/key.pem', keys.privateKey._eccPrivateKeyPem);
            
            // Hybrid PQC signing for ECC certificate
            if (usePqc) {
                const pqcKeys = await pqc.generateMLDSA87KeyPair();
                const rootPqcKeyPath = rootCaPath + '/pqc_private.bin';
                const certAsn1 = pki.certificateToAsn1(cert);
                
                if (fs.existsSync(rootPqcKeyPath)) {
                    const rootPqcKey = fs.readFileSync(rootPqcKeyPath);
                    const tbsCertDer = asn1.toDer(certAsn1.value[0]).getBytes();
                    const pqcSignature = await pqc.signMLDSA87(Buffer.from(tbsCertDer, 'binary'), new Uint8Array(rootPqcKey));
                    pqc.addHybridSignatureExtension(certAsn1, pqcSignature, pqc.OIDS.mlDsa87);
                    certPem = pki.certificateToPem(pki.certificateFromAsn1(certAsn1));
                }
                
                fs.outputFileSync(newCaPath + '/pqc_public.bin', Buffer.from(pqcKeys.publicKey));
                fs.outputFileSync(newCaPath + '/pqc_private.bin', Buffer.from(pqcKeys.privateKey));
            }
        } else {
            // RSA key - use node-forge (existing flow)
            const cert = buildCACert(keys, options, caCert);
            cert.sign(caKey, utils.createMessageDigest());
            
            certSerial = cert.serialNumber;
            certSubject = cert.subject.attributes;

            // Hybrid PQC signing
            if (usePqc) {
                const pqcKeys = await pqc.generateMLDSA87KeyPair();
                const rootPqcKeyPath = rootCaPath + '/pqc_private.bin';
                const certAsn1 = pki.certificateToAsn1(cert);
                
                if (fs.existsSync(rootPqcKeyPath)) {
                    const rootPqcKey = fs.readFileSync(rootPqcKeyPath);
                    const tbsCertDer = asn1.toDer(certAsn1.value[0]).getBytes();
                    const pqcSignature = await pqc.signMLDSA87(Buffer.from(tbsCertDer, 'binary'), new Uint8Array(rootPqcKey));
                    pqc.addHybridSignatureExtension(certAsn1, pqcSignature, pqc.OIDS.mlDsa87);
                }

                fs.outputFileSync(newCaPath + '/pqc_public.bin', Buffer.from(pqcKeys.publicKey));
                fs.outputFileSync(newCaPath + '/pqc_private.bin', Buffer.from(pqcKeys.privateKey));
                
                certPem = pki.certificateToPem(pki.certificateFromAsn1(certAsn1));
            } else {
                certPem = pki.certificateToPem(cert);
            }

            const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
            fs.outputFileSync(newCaPath + '/key.pem', privateKeyPem);
        }

        // Write certificate and serial
        fs.outputFileSync(newCaPath + '/crt.pem', certPem);
        fs.outputFileSync(newCaPath + '/serial.txt', '01');
        fs.outputFileSync(
            basePath + normalizeName(caName) + '/parent.txt',
            normalizeName(rootCaName)
        );

        audit.auditLog(audit.AUDIT_EVENTS.CA_INTERMEDIATE_CREATED, {
            caName: caName,
            rootCaName: rootCaName,
            subject: cert.subject.attributes,
            serialNumber: cert.serialNumber,
            keyType: keyType,
            keySize: keyType === 'rsa' ? keySize : 384,
            pqc: usePqc ? 'ML-DSA-87' : 'none'
        }, basePath);

        const bundleFile = `${rootCaPath}/${normalizeName(rootCaName)}.ca-bundle`;
        const caBundlePath = `${newCaPath}/${normalizeName(caName)}.ca-bundle`;
        const caCertPem = fs.readFileSync(newCaPath + '/crt.pem', 'utf8');
        if (fs.existsSync(bundleFile)) {
            const rootBundle = fs.readFileSync(bundleFile, 'utf8');
            fs.outputFileSync(caBundlePath, caCertPem + rootBundle);
        } else {
            fs.outputFileSync(caBundlePath, caCertPem + rootCaCertPem);
        }

        console.log('Certificate authority ' + caName + ' was created.');
    } else {
        console.log('Certificate authority ' + caName + ' already exists.');
    }
}

function listCACerts(path) {
    utils.listCerts('ca', path);
}

function removeCACert(name, basePath = 'pki/') {
    if (basePath.substr(-1) !== '/') basePath += '/';

    if (fs.existsSync(basePath + '/' + normalizeName(name))) {
        fs.removeSync(basePath + '/' + normalizeName(name));
        
        audit.auditLog(audit.AUDIT_EVENTS.CA_REMOVED, {
            caName: name
        }, basePath);

        console.log(
            'Certificate Authority ' + name + ' and all associated certificates were removed.'
        );
    } else {
        console.log('Certificate Authority ' + name + ' does not exist.');
    }
}

module.exports = {
    createCACert,
    createIntermediateCACert,
    listCACerts,
    removeCACert,
};
