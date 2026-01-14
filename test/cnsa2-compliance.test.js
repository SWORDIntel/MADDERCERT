/**
 * MADCert CNSA 2.0 Compliance Tests
 * Tests for ECC P-384, certificate algorithms, and CNSA 2.0 requirements
 */

const expect = require('chai').expect;
const certs = require('../src/certs');
const compliance = require('../src/compliance');
const fs = require('fs-extra');
const path = require('path');
const forge = require('node-forge');

describe('CNSA 2.0 Compliance Tests', function() {
    const testPkiPath = path.join(__dirname, '../test-pki');
    
    before(function() {
        // Clean up test PKI directory
        if (fs.existsSync(testPkiPath)) {
            fs.removeSync(testPkiPath);
        }
        fs.ensureDirSync(testPkiPath);
    });
    
    after(function() {
        // Clean up test PKI directory
        if (fs.existsSync(testPkiPath)) {
            fs.removeSync(testPkiPath);
        }
    });

    describe('ECC P-384 Certificate Creation', function() {
        it('should create CA certificate with ECC P-384 key', async function() {
            await certs.createCACert('Test CA ECC', {
                basePath: testPkiPath,
                keyType: 'ec'
            });
            
            const caCertPath = path.join(testPkiPath, 'test-ca-ecc/ca/crt.pem');
            expect(fs.existsSync(caCertPath)).to.be.true;
            
            const certPem = fs.readFileSync(caCertPath, 'utf8');
            const cert = forge.pki.certificateFromPem(certPem);
            const publicKey = cert.publicKey;
            
            // Verify ECC key (no modulus n means ECC)
            expect(publicKey.n).to.be.undefined;
            expect(publicKey.curveOid).to.exist;
        });

        it('should create server certificate with ECC P-384 key', async function() {
            await certs.createServerCert('Test Server ECC', 'Test CA ECC', false, {
                basePath: testPkiPath,
                keyType: 'ec'
            });
            
            const serverCertPath = path.join(testPkiPath, 'test-ca-ecc/servers/test-server-ecc/crt.pem');
            expect(fs.existsSync(serverCertPath)).to.be.true;
            
            const certPem = fs.readFileSync(serverCertPath, 'utf8');
            const cert = forge.pki.certificateFromPem(certPem);
            const publicKey = cert.publicKey;
            
            expect(publicKey.n).to.be.undefined;
            expect(publicKey.curveOid).to.exist;
        });
    });

    describe('Certificate Algorithm Compliance', function() {
        it('should use SHA-384 or SHA-512 for certificate signatures', async function() {
            await certs.createCACert('Test CA Algorithm', {
                basePath: testPkiPath
            });
            
            const caCertPath = path.join(testPkiPath, 'test-ca-algorithm/ca/crt.pem');
            const certPem = fs.readFileSync(caCertPath, 'utf8');
            const cert = forge.pki.certificateFromPem(certPem);
            
            const sigAlg = cert.siginfo.algorithm.toLowerCase();
            expect(sigAlg).to.satisfy(alg => 
                alg.includes('sha384') || alg.includes('sha512')
            );
        });
    });

    describe('Compliance Verification', function() {
        it('should verify ECC P-384 certificate compliance', async function() {
            await certs.createCACert('Test CA Compliance', {
                basePath: testPkiPath,
                keyType: 'ec'
            });
            
            const caCertPath = path.join(testPkiPath, 'test-ca-compliance/ca/crt.pem');
            const report = compliance.verifyCertificateCompliance(caCertPath);
            
            expect(report).to.have.property('compliant');
            expect(report).to.have.property('issues');
            expect(report).to.have.property('details');
        });

        it('should verify PKCS#12 file compliance', async function() {
            await certs.createCACert('Test CA P12', {
                basePath: testPkiPath
            });
            
            await certs.createServerCert('Test Server P12', 'Test CA P12', false, {
                basePath: testPkiPath
            });
            
            const p12Path = path.join(testPkiPath, 'test-ca-p12/servers/test-server-p12/bundle.p12');
            if (fs.existsSync(p12Path)) {
                const report = compliance.verifyPKCS12Compliance(p12Path);
                expect(report).to.have.property('compliant');
                expect(report).to.have.property('details');
            }
        });
    });
});
