/**
 * MADCert Certificate Lifecycle Tests
 * Tests for revocation, CRL generation, OCSP, renewal
 */

const expect = require('chai').expect;
const certs = require('../src/certs');
const crl = require('../src/crl');
const renewal = require('../src/renewal');
const fs = require('fs-extra');
const path = require('path');
const forge = require('node-forge');

describe('Certificate Lifecycle Tests', function() {
    const testPkiPath = path.join(__dirname, '../test-pki-lifecycle');
    
    before(async function() {
        if (fs.existsSync(testPkiPath)) {
            fs.removeSync(testPkiPath);
        }
        fs.ensureDirSync(testPkiPath);
        
        // Create test CA
        await certs.createCACert('Test CA Lifecycle', {
            basePath: testPkiPath
        });
    });
    
    after(function() {
        if (fs.existsSync(testPkiPath)) {
            fs.removeSync(testPkiPath);
        }
    });

    describe('Certificate Revocation', function() {
        it('should revoke a certificate and update CRL', async function() {
            await certs.createServerCert('Test Server Revoke', 'Test CA Lifecycle', false, {
                basePath: testPkiPath
            });
            
            const certPath = path.join(testPkiPath, 'test-ca-lifecycle/servers/test-server-revoke/crt.pem');
            const certPem = fs.readFileSync(certPath, 'utf8');
            const cert = forge.pki.certificateFromPem(certPem);
            const serial = cert.serialNumber;
            
            crl.revokeCertificate('Test CA Lifecycle', serial, 'keyCompromise', {
                basePath: testPkiPath
            });
            
            const crlPath = path.join(testPkiPath, 'test-ca-lifecycle/ca/ca.crl');
            expect(fs.existsSync(crlPath)).to.be.true;
        });
    });

    describe('CRL Generation', function() {
        it('should generate CRL for CA', function() {
            const crlPem = crl.generateCRL('Test CA Lifecycle', {
                basePath: testPkiPath
            });
            
            expect(crlPem).to.exist;
            expect(crlPem).to.include('BEGIN X509 CRL');
        });
    });

    describe('Certificate Renewal', function() {
        it('should detect certificates needing renewal', async function() {
            await certs.createServerCert('Test Server Renew', 'Test CA Lifecycle', false, {
                basePath: testPkiPath,
                expired: true  // Create expired certificate
            });
            
            const certPath = path.join(testPkiPath, 'test-ca-lifecycle/servers/test-server-renew/crt.pem');
            const certPem = fs.readFileSync(certPath, 'utf8');
            const cert = forge.pki.certificateFromPem(certPem);
            
            const needsRenewal = renewal.isRenewalNeeded(cert, 30);
            expect(needsRenewal).to.be.true;
        });
    });
});
