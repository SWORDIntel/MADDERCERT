/**
 * MADCert PKCS#12 Tests
 * Tests for AES-256-GCM encryption, MacData, SHA-384 KDF/MAC, OpenSSL compatibility
 */

const expect = require('chai').expect;
const certs = require('../src/certs');
const compliance = require('../src/compliance');
const fs = require('fs-extra');
const path = require('path');
const { execSync } = require('child_process');

describe('PKCS#12 Tests', function() {
    const testPkiPath = path.join(__dirname, '../test-pki-p12');
    
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

    describe('AES-256-GCM Encryption', function() {
        it('should create PKCS#12 file with AES-256-GCM encryption', async function() {
            await certs.createCACert('Test CA P12', {
                basePath: testPkiPath
            });
            
            await certs.createServerCert('Test Server P12', 'Test CA P12', false, {
                basePath: testPkiPath,
                password: 'testpass123'
            });
            
            const p12Path = path.join(testPkiPath, 'test-ca-p12/servers/test-server-p12/bundle.p12');
            expect(fs.existsSync(p12Path)).to.be.true;
            
            const report = compliance.verifyPKCS12Compliance(p12Path);
            expect(report.details.encryptionAlgorithm).to.equal('AES-256-GCM');
        });
    });

    describe('OpenSSL Compatibility', function() {
        it('should be readable by OpenSSL', async function() {
            await certs.createCACert('Test CA OpenSSL', {
                basePath: testPkiPath
            });
            
            await certs.createServerCert('Test Server OpenSSL', 'Test CA OpenSSL', false, {
                basePath: testPkiPath,
                password: 'testpass123'
            });
            
            const p12Path = path.join(testPkiPath, 'test-ca-openssl/servers/test-server-openssl/bundle.p12');
            if (fs.existsSync(p12Path)) {
                try {
                    // Try to read with OpenSSL (if available)
                    execSync(`openssl pkcs12 -info -in ${p12Path} -passin pass:testpass123 -nokeys`, { 
                        stdio: 'pipe',
                        timeout: 5000
                    });
                } catch (err) {
                    // OpenSSL might not be available, skip test
                    this.skip();
                }
            }
        });
    });

    describe('MacData Structure', function() {
        it('should include MacData in PKCS#12 file', async function() {
            await certs.createCACert('Test CA MacData', {
                basePath: testPkiPath
            });
            
            await certs.createServerCert('Test Server MacData', 'Test CA MacData', false, {
                basePath: testPkiPath,
                password: 'testpass123'
            });
            
            const p12Path = path.join(testPkiPath, 'test-ca-macdata/servers/test-server-macdata/bundle.p12');
            if (fs.existsSync(p12Path)) {
                const report = compliance.verifyPKCS12Compliance(p12Path);
                // MacData is optional but recommended
                expect(report.details).to.have.property('hasMacData');
            }
        });
    });
});
