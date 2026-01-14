/**
 * MADCert CRL Management Module
 * Implements CRL generation and revocation tracking
 */

const forge = require('node-forge');
const fs = require('fs-extra');
const path = require('path');
const utils = require('./utils');
const audit = require('./audit');
const _ = require('lodash');

const pki = forge.pki;
const normalizeName = utils.normalizeName;

/**
 * Generates a CRL for a specific CA
 */
function generateCRL(caName, options = {}) {
    const basePath = _.get(options, 'basePath', 'pki/');
    const caPath = path.join(basePath, normalizeName(caName), '/ca/');
    const crlPath = path.join(caPath, 'ca.crl');
    const dbPath = path.join(caPath, 'index.txt');

    if (!fs.existsSync(caPath)) {
        throw new Error(`CA ${caName} not found`);
    }

    const caCertPem = fs.readFileSync(path.join(caPath, 'crt.pem'), 'utf8');
    const caKeyPem = fs.readFileSync(path.join(caPath, 'key.pem'), 'utf8');
    const caCert = pki.certificateFromPem(caCertPem);
    const caKey = pki.privateKeyFromPem(caKeyPem);

    const crl = pki.createCRL();
    crl.issuerName = caCert.subject.attributes;
    crl.lastUpdate = new Date();
    crl.nextUpdate = new Date();
    crl.nextUpdate.setDate(crl.lastUpdate.getDate() + 30); // Valid for 30 days

    // Load revoked certificates from index.txt
    if (fs.existsSync(dbPath)) {
        const dbContent = fs.readFileSync(dbPath, 'utf8');
        const lines = dbContent.split('\n');
        lines.forEach(line => {
            if (line.startsWith('R')) { // Revoked
                const parts = line.split('\t');
                const serial = parts[3];
                const revocationDate = new Date(parts[2]);
                crl.revokeCertificate(serial, revocationDate);
            }
        });
    }

    crl.sign(caKey, utils.createMessageDigest());
    const crlPem = pki.crlToPem(crl);
    fs.outputFileSync(crlPath, crlPem);

    return crlPem;
}

/**
 * Revokes a certificate and updates the CA database
 */
function revokeCertificate(caName, serial, reason = 'unspecified', options = {}) {
    const basePath = _.get(options, 'basePath', 'pki/');
    const caPath = path.join(basePath, normalizeName(caName), '/ca/');
    const dbPath = path.join(caPath, 'index.txt');

    if (!fs.existsSync(caPath)) {
        throw new Error(`CA ${caName} not found`);
    }

    // OpenSSL index.txt format:
    // status (V/R/E) \t expiry \t revocation_date \t serial \t filename \t subject
    let dbContent = fs.existsSync(dbPath) ? fs.readFileSync(dbPath, 'utf8') : '';
    const lines = dbContent.split('\n');
    let found = false;
    const newLines = lines.map(line => {
        if (line.includes(`\t${serial}\t`)) {
            found = true;
            const parts = line.split('\t');
            parts[0] = 'R';
            parts[2] = new Date().toISOString().replace(/Z$/, 'Z');
            return parts.join('\t');
        }
        return line;
    });

    if (!found) {
        throw new Error(`Certificate with serial ${serial} not found in CA database`);
    }

    fs.outputFileSync(dbPath, newLines.join('\n'));

    audit.auditLog(audit.AUDIT_EVENTS.CERT_REVOKED, {
        caName: caName,
        serialNumber: serial,
        reason: reason
    }, basePath);

    // Regenerate CRL
    return generateCRL(caName, options);
}

module.exports = {
    generateCRL,
    revokeCertificate
};
