/**
 * MADCert Chain Validation Module
 */

const forge = require('node-forge');
const fs = require('fs-extra');
const path = require('path');

const pki = forge.pki;

/**
 * Validates a certificate chain
 * @param {String} certPem Certificate to validate
 * @param {Array} chainPem Array of issuer certificates
 */
function validateChain(certPem, chainPem = []) {
    try {
        const cert = pki.certificateFromPem(certPem);
        const chain = chainPem.map(p => pki.certificateFromPem(p));
        
        const results = {
            valid: true,
            errors: [],
            expired: false,
            signaturesValid: true
        };

        // Check expiration
        const now = new Date();
        if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
            results.valid = false;
            results.expired = true;
            results.errors.push('Certificate is expired or not yet valid');
        }

        // Verify signatures
        let currentCert = cert;
        for (let i = 0; i < chain.length; i++) {
            const issuer = chain[i];
            try {
                if (!issuer.verify(currentCert)) {
                    results.signaturesValid = false;
                    results.valid = false;
                    results.errors.push(`Signature verification failed at depth ${i}`);
                }
            } catch (e) {
                results.signaturesValid = false;
                results.valid = false;
                results.errors.push(`Signature verification error at depth ${i}: ${e.message}`);
            }
            currentCert = issuer;
        }

        return results;
    } catch (e) {
        return {
            valid: false,
            errors: [`Validation error: ${e.message}`]
        };
    }
}

module.exports = {
    validateChain
};
