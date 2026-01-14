/**
 * MADCert CNSA 2.0 Compliance Verification Module
 * Provides automated compliance checking for certificates, PKCS#12 files, and CAs
 */

const forge = require('node-forge');
const fs = require('fs-extra');
const path = require('path');
const _ = require('lodash');
const utils = require('./utils');
const pkcs12_cnsa2 = require('./pkcs12_cnsa2');

const pki = forge.pki;
const normalizeName = utils.normalizeName;

// CNSA 2.0 Compliance Requirements
const CNSA2_REQUIREMENTS = {
    MIN_RSA_KEY_SIZE: 3072,
    DEFAULT_RSA_KEY_SIZE: 4096,
    ECC_CURVE: 'secp384r1',
    MIN_HASH_ALGORITHM: 'sha384',
    APPROVED_HASH_ALGORITHMS: ['sha384', 'sha512'],
    APPROVED_SYMMETRIC_ALGORITHMS: ['aes256-gcm'],
    MIN_PBKDF2_ITERATIONS: 100000,
    APPROVED_PQC_ALGORITHMS: ['ML-KEM-1024', 'ML-DSA-87']
};

/**
 * Verifies a single certificate for CNSA 2.0 compliance
 * @param {String} certPath Path to certificate PEM file
 * @returns {Object} Compliance report
 */
function verifyCertificateCompliance(certPath) {
    const report = {
        compliant: true,
        issues: [],
        warnings: [],
        details: {}
    };

    if (!fs.existsSync(certPath)) {
        report.compliant = false;
        report.issues.push(`Certificate file not found: ${certPath}`);
        return report;
    }

    try {
        const certPem = fs.readFileSync(certPath, 'utf8');
        const cert = pki.certificateFromPem(certPem);

        // Check signature algorithm
        const sigAlg = cert.siginfo.algorithm;
        report.details.signatureAlgorithm = sigAlg;
        if (!CNSA2_REQUIREMENTS.APPROVED_HASH_ALGORITHMS.some(alg => sigAlg.toLowerCase().includes(alg))) {
            report.compliant = false;
            report.issues.push(`Signature algorithm ${sigAlg} is not CNSA 2.0 compliant. Required: SHA-384 or SHA-512`);
        }

        // Check public key type and size
        const publicKey = cert.publicKey;
        if (publicKey.n) {
            // RSA key
            const keySize = publicKey.n.bitLength();
            report.details.keyType = 'RSA';
            report.details.keySize = keySize;
            if (keySize < CNSA2_REQUIREMENTS.MIN_RSA_KEY_SIZE) {
                report.compliant = false;
                report.issues.push(`RSA key size ${keySize} is below CNSA 2.0 minimum of ${CNSA2_REQUIREMENTS.MIN_RSA_KEY_SIZE} bits`);
            } else if (keySize < CNSA2_REQUIREMENTS.DEFAULT_RSA_KEY_SIZE) {
                report.warnings.push(`RSA key size ${keySize} is below recommended ${CNSA2_REQUIREMENTS.DEFAULT_RSA_KEY_SIZE} bits`);
            }
        } else if (publicKey.curveOid) {
            // ECC key
            const curveName = publicKey.curveOid;
            report.details.keyType = 'ECC';
            report.details.curve = curveName;
            if (curveName !== CNSA2_REQUIREMENTS.ECC_CURVE) {
                report.compliant = false;
                report.issues.push(`ECC curve ${curveName} is not CNSA 2.0 compliant. Required: ${CNSA2_REQUIREMENTS.ECC_CURVE}`);
            }
        } else {
            report.compliant = false;
            report.issues.push('Unsupported key type or unable to determine key parameters');
        }

        // Check validity period
        const now = new Date();
        const notBefore = cert.validity.notBefore;
        const notAfter = cert.validity.notAfter;
        report.details.validity = {
            notBefore: notBefore.toISOString(),
            notAfter: notAfter.toISOString(),
            isValid: now >= notBefore && now <= notAfter
        };

        if (now > notAfter) {
            report.warnings.push('Certificate has expired');
        } else if (now < notBefore) {
            report.warnings.push('Certificate is not yet valid');
        }

        // Check for PQC extensions (optional but recommended)
        const extensions = cert.extensions || [];
        const hasPQC = extensions.some(ext => 
            ext.id === '2.5.29.74' || // altSignatureAlgorithm
            ext.id === '2.5.29.75'    // altSignatureValue
        );
        report.details.hasPQC = hasPQC;
        if (!hasPQC) {
            report.warnings.push('Certificate does not include Post-Quantum Cryptography extensions (recommended for CNSA 2.0)');
        }

    } catch (err) {
        report.compliant = false;
        report.issues.push(`Failed to parse certificate: ${err.message}`);
    }

    return report;
}

/**
 * Verifies a PKCS#12 file for CNSA 2.0 compliance
 * @param {String} p12Path Path to PKCS#12 file
 * @returns {Object} Compliance report
 */
function verifyPKCS12Compliance(p12Path) {
    const report = {
        compliant: true,
        issues: [],
        warnings: [],
        details: {}
    };

    if (!fs.existsSync(p12Path)) {
        report.compliant = false;
        report.issues.push(`PKCS#12 file not found: ${p12Path}`);
        return report;
    }

    try {
        // Read PKCS#12 file and check structure
        const p12Data = fs.readFileSync(p12Path);
        const p12Hex = forge.util.bytesToHex(p12Data);

        // Check for AES-256-GCM OID (2.16.840.1.101.3.4.1.46)
        // DER encoding: 06 09 60 86 48 01 65 03 04 01 2a
        const aes256GCMOid = '060960864801650304012a';
        const hasAES256GCM = p12Hex.includes(aes256GCMOid);
        report.details.encryptionAlgorithm = hasAES256GCM ? 'AES-256-GCM' : 'Unknown';
        
        if (!hasAES256GCM) {
            report.compliant = false;
            report.issues.push('PKCS#12 encryption algorithm is not AES-256-GCM (CNSA 2.0 requirement)');
        }

        // Check for PBKDF2-SHA-384 OID (1.2.840.113549.1.5.12)
        // SHA-384 OID: 2.16.840.1.101.3.4.2.2
        const pbkdf2Oid = '06052a864886f70d030c'; // PBKDF2
        const sha384Oid = '0609608648016503040202'; // SHA-384
        const hasPBKDF2SHA384 = p12Hex.includes(pbkdf2Oid) && p12Hex.includes(sha384Oid);
        report.details.kdfAlgorithm = hasPBKDF2SHA384 ? 'PBKDF2-SHA-384' : 'Unknown';
        
        if (!hasPBKDF2SHA384) {
            report.compliant = false;
            report.issues.push('PKCS#12 KDF is not PBKDF2-SHA-384 (CNSA 2.0 requirement)');
        }

        // Check for MacData (optional but recommended for compatibility)
        // MacData structure indicates HMAC-SHA-384 usage
        const macDataOid = '0609608648016503040202'; // SHA-384 in DigestInfo
        const hasMacData = p12Hex.includes(macDataOid);
        report.details.hasMacData = hasMacData;
        if (!hasMacData) {
            report.warnings.push('PKCS#12 file does not include MacData (may cause compatibility issues with some parsers)');
        }

    } catch (err) {
        report.compliant = false;
        report.issues.push(`Failed to analyze PKCS#12 file: ${err.message}`);
    }

    return report;
}

/**
 * Verifies an entire CA for CNSA 2.0 compliance
 * @param {String} caPath Path to CA directory
 * @returns {Object} Compliance report
 */
function verifyCACompliance(caPath) {
    const report = {
        compliant: true,
        issues: [],
        warnings: [],
        details: {
            ca: {},
            certificates: [],
            pkcs12Files: []
        }
    };

    if (!fs.existsSync(caPath)) {
        report.compliant = false;
        report.issues.push(`CA directory not found: ${caPath}`);
        return report;
    }

    // Check CA certificate
    const caCertPath = path.join(caPath, 'ca', 'crt.pem');
    if (fs.existsSync(caCertPath)) {
        const caReport = verifyCertificateCompliance(caCertPath);
        report.details.ca = caReport.details;
        if (!caReport.compliant) {
            report.compliant = false;
            report.issues.push(...caReport.issues.map(issue => `CA Certificate: ${issue}`));
        }
        report.warnings.push(...caReport.warnings.map(warn => `CA Certificate: ${warn}`));
    } else {
        report.compliant = false;
        report.issues.push('CA certificate not found');
    }

    // Check server certificates
    const serversPath = path.join(caPath, 'servers');
    if (fs.existsSync(serversPath)) {
        const serverDirs = fs.readdirSync(serversPath);
        serverDirs.forEach(serverName => {
            const certPath = path.join(serversPath, serverName, 'crt.pem');
            const p12Path = path.join(serversPath, serverName, 'bundle.p12');
            
            if (fs.existsSync(certPath)) {
                const certReport = verifyCertificateCompliance(certPath);
                report.details.certificates.push({
                    name: serverName,
                    type: 'server',
                    ...certReport.details
                });
                if (!certReport.compliant) {
                    report.compliant = false;
                    report.issues.push(...certReport.issues.map(issue => `Server ${serverName}: ${issue}`));
                }
            }
            
            if (fs.existsSync(p12Path)) {
                const p12Report = verifyPKCS12Compliance(p12Path);
                report.details.pkcs12Files.push({
                    name: serverName,
                    type: 'server',
                    ...p12Report.details
                });
                if (!p12Report.compliant) {
                    report.compliant = false;
                    report.issues.push(...p12Report.issues.map(issue => `Server ${serverName} P12: ${issue}`));
                }
            }
        });
    }

    // Check user certificates
    const usersPath = path.join(caPath, 'users');
    if (fs.existsSync(usersPath)) {
        const userDirs = fs.readdirSync(usersPath);
        userDirs.forEach(userName => {
            const certPath = path.join(usersPath, userName, 'crt.pem');
            const p12Path = path.join(usersPath, userName, 'bundle.p12');
            
            if (fs.existsSync(certPath)) {
                const certReport = verifyCertificateCompliance(certPath);
                report.details.certificates.push({
                    name: userName,
                    type: 'user',
                    ...certReport.details
                });
                if (!certReport.compliant) {
                    report.compliant = false;
                    report.issues.push(...certReport.issues.map(issue => `User ${userName}: ${issue}`));
                }
            }
            
            if (fs.existsSync(p12Path)) {
                const p12Report = verifyPKCS12Compliance(p12Path);
                report.details.pkcs12Files.push({
                    name: userName,
                    type: 'user',
                    ...p12Report.details
                });
                if (!p12Report.compliant) {
                    report.compliant = false;
                    report.issues.push(...p12Report.issues.map(issue => `User ${userName} P12: ${issue}`));
                }
            }
        });
    }

    return report;
}

/**
 * Generates a comprehensive compliance report for a PKI directory
 * @param {String} basePath Base path for PKI storage
 * @returns {Object} Full compliance report
 */
function generateComplianceReport(basePath = 'pki/') {
    if (basePath.substr(-1) !== '/') basePath += '/';

    const report = {
        compliant: true,
        summary: {
            totalCAs: 0,
            compliantCAs: 0,
            totalCertificates: 0,
            compliantCertificates: 0,
            totalP12Files: 0,
            compliantP12Files: 0
        },
        cas: [],
        issues: [],
        warnings: []
    };

    if (!fs.existsSync(basePath)) {
        report.compliant = false;
        report.issues.push(`PKI directory not found: ${basePath}`);
        return report;
    }

    const caDirs = fs.readdirSync(basePath).filter(f => {
        const fullPath = path.join(basePath, f);
        return fs.lstatSync(fullPath).isDirectory();
    });

    report.summary.totalCAs = caDirs.length;

    caDirs.forEach(caName => {
        const caPath = path.join(basePath, caName);
        const caReport = verifyCACompliance(caPath);
        
        report.cas.push({
            name: caName,
            compliant: caReport.compliant,
            details: caReport.details
        });

        if (caReport.compliant) {
            report.summary.compliantCAs++;
        } else {
            report.compliant = false;
        }

        report.summary.totalCertificates += caReport.details.certificates.length;
        report.summary.compliantCertificates += caReport.details.certificates.filter(c => 
            !caReport.issues.some(issue => issue.includes(c.name))
        ).length;

        report.summary.totalP12Files += caReport.details.pkcs12Files.length;
        report.summary.compliantP12Files += caReport.details.pkcs12Files.filter(p => 
            !caReport.issues.some(issue => issue.includes(p.name))
        ).length;

        report.issues.push(...caReport.issues);
        report.warnings.push(...caReport.warnings);
    });

    return report;
}

module.exports = {
    verifyCertificateCompliance,
    verifyPKCS12Compliance,
    verifyCACompliance,
    generateComplianceReport,
    CNSA2_REQUIREMENTS
};
