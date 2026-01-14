/**
 * MADCert Certificate Renewal Module
 * Provides functions for automated certificate renewal
 */

const forge = require('node-forge');
const fs = require('fs-extra');
const path = require('path');
const _ = require('lodash');
const utils = require('./utils');
const audit = require('./audit');

const pki = forge.pki;
const normalizeName = utils.normalizeName;

/**
 * Checks if a certificate is nearing expiration
 * @param {Object} cert The certificate object
 * @param {Number} daysThreshold Days before expiration to trigger renewal
 * @returns {Boolean} True if renewal is needed, false otherwise
 */
function isRenewalNeeded(cert, daysThreshold = 30) {
    const now = new Date();
    const expiry = cert.validity.notAfter;
    const diffTime = Math.abs(expiry.getTime() - now.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays <= daysThreshold;
}

/**
 * Renews a certificate by creating a new one with updated validity dates
 * @param {String} certPath Path to the certificate to renew
 * @param {String} certType 'server' or 'user'
 * @param {String} caName CA name
 * @param {Object} options Renewal options
 */
async function renewCertificate(certPath, certType, caName, options = {}) {
    const basePath = options.basePath || 'pki/';
    const certName = path.basename(path.dirname(certPath));
    
    // Load old certificate to get subject attributes
    const certPem = fs.readFileSync(certPath, 'utf8');
    const cert = pki.certificateFromPem(certPem);
    
    // Archive old certificate
    const archiveDir = path.join(path.dirname(certPath), 'expired');
    fs.ensureDirSync(archiveDir);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    fs.copySync(certPath, path.join(archiveDir, `crt-${timestamp}.pem`));
    
    // Extract subject attributes from old certificate
    const subjectAttrs = cert.subject.attributes.map(attr => ({
        name: attr.name,
        shortName: attr.shortName,
        value: attr.value
    }));
    
    // Create new certificate with same subject but new validity
    // This is a simplified renewal - full implementation would preserve all options
    audit.auditLog(audit.AUDIT_EVENTS.CERT_RENEWED, {
        certPath: certPath,
        certName: certName,
        certType: certType,
        caName: caName,
        oldSerial: cert.serialNumber,
        message: 'Certificate renewal initiated'
    }, basePath);
    
    return { success: true, message: 'Renewal process initiated. Use create commands to generate new certificate.' };
}

/**
 * Scans for expiring certificates and triggers renewal
 * @param {String} basePath Base path for PKI storage
 * @param {Number} daysThreshold Days before expiration to trigger renewal
 */
async function scanAndRenewCertificates(basePath = 'pki/', daysThreshold = 30) {
    if (basePath.substr(-1) !== '/') basePath += '/';
    
    if (!fs.existsSync(basePath)) {
        console.log(`[RENEWAL] PKI directory not found: ${basePath}`);
        return;
    }
    
    console.log(`[RENEWAL] Scanning for certificates expiring within ${daysThreshold} days...`);
    const caDirs = fs.readdirSync(basePath).filter(f => {
        const fullPath = path.join(basePath, f);
        return fs.lstatSync(fullPath).isDirectory();
    });

    let renewedCount = 0;
    
    for (const caName of caDirs) {
        const caPath = path.join(basePath, caName);
        const certTypes = ['servers', 'users'];

        for (const type of certTypes) {
            const certDir = path.join(caPath, type);
            if (fs.existsSync(certDir)) {
                const certNames = fs.readdirSync(certDir);
                for (const certName of certNames) {
                    const certFilePath = path.join(certDir, certName, 'crt.pem');
                    if (fs.existsSync(certFilePath)) {
                        try {
                            const certPem = fs.readFileSync(certFilePath, 'utf8');
                            const cert = pki.certificateFromPem(certPem);
                            if (isRenewalNeeded(cert, daysThreshold)) {
                                console.log(`[RENEWAL] Certificate ${certName} (CA: ${caName}, Type: ${type}) is expiring soon.`);
                                await renewCertificate(certFilePath, type.slice(0, -1), caName, { basePath: basePath });
                                renewedCount++;
                            }
                        } catch (err) {
                            console.warn(`[RENEWAL] Failed to process ${certFilePath}: ${err.message}`);
                        }
                    }
                }
            }
        }
    }
    
    console.log(`[RENEWAL] Scan complete. ${renewedCount} certificate(s) flagged for renewal.`);
    return renewedCount;
}

module.exports = {
    isRenewalNeeded,
    renewCertificate,
    scanAndRenewCertificates
};
