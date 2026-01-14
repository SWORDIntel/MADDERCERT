/**
 * MADCert Audit Logging Tests
 * Tests for audit logging, hash verification, tamper detection, query functions
 */

const expect = require('chai').expect;
const audit = require('../src/audit');
const certs = require('../src/certs');
const fs = require('fs-extra');
const path = require('path');
const forge = require('node-forge');

describe('Audit Logging Tests', function() {
    const testPkiPath = path.join(__dirname, '../test-pki-audit');
    
    before(function() {
        if (fs.existsSync(testPkiPath)) {
            fs.removeSync(testPkiPath);
        }
        fs.ensureDirSync(testPkiPath);
    });
    
    after(function() {
        if (fs.existsSync(testPkiPath)) {
            fs.removeSync(testPkiPath);
        }
    });

    describe('Audit Log Creation', function() {
        it('should create audit log entries for CA creation', async function() {
            await certs.createCACert('Test CA Audit', {
                basePath: testPkiPath
            });
            
            const auditPath = path.join(testPkiPath, 'audit.log');
            expect(fs.existsSync(auditPath)).to.be.true;
            
            const auditContent = fs.readFileSync(auditPath, 'utf8');
            expect(auditContent).to.include('CA_CREATED');
        });

        it('should include tamper-evident hash in audit entries', async function() {
            await certs.createCACert('Test CA Hash', {
                basePath: testPkiPath
            });
            
            const auditPath = path.join(testPkiPath, 'audit.log');
            const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n');
            const lastEntry = JSON.parse(lines[lines.length - 1]);
            
            expect(lastEntry).to.have.property('hash');
            expect(lastEntry.hash).to.match(/^[a-f0-9]{96}$/); // SHA-384 hex is 96 chars
        });
    });

    describe('Audit Log Query', function() {
        it('should query audit log by event type', async function() {
            await certs.createCACert('Test CA Query', {
                basePath: testPkiPath
            });
            
            const results = audit.queryAuditLog({ event: 'CA_CREATED' }, testPkiPath);
            expect(results.length).to.be.greaterThan(0);
            expect(results[0].event).to.equal('CA_CREATED');
        });

        it('should query audit log by user', async function() {
            const results = audit.queryAuditLog({ user: process.env.USER || 'unknown' }, testPkiPath);
            expect(Array.isArray(results)).to.be.true;
        });
    });

    describe('Hash Verification', function() {
        it('should verify hash integrity of audit entries', async function() {
            await certs.createCACert('Test CA Verify', {
                basePath: testPkiPath
            });
            
            const auditPath = path.join(testPkiPath, 'audit.log');
            const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n');
            const lastEntry = JSON.parse(lines[lines.length - 1]);
            
            // Recalculate hash
            const entryCopy = Object.assign({}, lastEntry);
            delete entryCopy.hash;
            const md = forge.md.sha384.create();
            md.update(JSON.stringify(entryCopy));
            const calculatedHash = md.digest().toHex();
            
            expect(calculatedHash).to.equal(lastEntry.hash);
        });
    });
});
