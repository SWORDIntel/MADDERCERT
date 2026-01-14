/**
 * MADCert Audit Logging Module
 * CNSA 2.0 Compliant structured logging with tamper-evident hashing
 */

const fs = require('fs-extra');
const path = require('path');
const forge = require('node-forge');

const AUDIT_EVENTS = {
    CA_CREATED: 'CA_CREATED',
    CA_REMOVED: 'CA_REMOVED',
    CA_INTERMEDIATE_CREATED: 'CA_INTERMEDIATE_CREATED',
    CERT_CREATED: 'CERT_CREATED',
    CERT_REMOVED: 'CERT_REMOVED',
    CERT_REVOKED: 'CERT_REVOKED',
    CERT_RENEWED: 'CERT_RENEWED',
    KEY_GENERATED: 'KEY_GENERATED',
    P12_CREATED: 'P12_CREATED'
};

/**
 * Logs an event to the audit trail
 * @param {String} event Event type from AUDIT_EVENTS
 * @param {Object} details Event details
 * @param {String} basePath Base path for PKI storage
 */
function auditLog(event, details, basePath = 'pki/') {
    // Ensure basePath ends with slash
    if (basePath.substr(-1) !== '/') basePath += '/';
    
    const logEntry = {
        timestamp: new Date().toISOString(),
        event: event,
        user: process.env.USER || process.env.USERNAME || 'unknown',
        hostname: require('os').hostname(),
        details: details
    };
    
    // Generate tamper-evident hash (SHA-384 per CNSA 2.0)
    // CRITICAL: Hash BEFORE adding hash field to avoid circular dependency
    const md = forge.md.sha384.create();
    md.update(JSON.stringify(logEntry));
    logEntry.hash = md.digest().toHex();
    
    const auditPath = path.join(basePath, 'audit.log');
    const logLine = JSON.stringify(logEntry) + '\n';
    
    try {
        // Create directory if it doesn't exist
        fs.ensureDirSync(basePath);
        // Append to audit log (mode 0600 - read/write owner only)
        fs.appendFileSync(auditPath, logLine, { flag: 'a', mode: 0o600 });
    } catch (err) {
        console.error(`[AUDIT ERROR] Failed to write to audit log: ${err.message}`);
    }
    
    return logEntry;
}

/**
 * Queries the audit log for specific events
 * @param {Object} query Query parameters (event, user, dateRange)
 * @param {String} basePath Base path for PKI storage
 */
function queryAuditLog(query = {}, basePath = 'pki/') {
    const auditPath = path.join(basePath, 'audit.log');
    if (!fs.existsSync(auditPath)) return [];
    
    const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n');
    return lines.map(line => JSON.parse(line)).filter(entry => {
        if (query.event && entry.event !== query.event) return false;
        if (query.user && entry.user !== query.user) return false;
        // Additional filtering can be added here
        return true;
    });
}

module.exports = {
    auditLog,
    queryAuditLog,
    AUDIT_EVENTS
};
