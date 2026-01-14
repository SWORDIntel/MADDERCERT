/**
 * MADCert Post-Quantum Cryptography Tests
 * Tests for ML-KEM-1024, ML-DSA-87, hybrid signatures via DSSSL
 */

const expect = require('chai').expect;
const certs = require('../src/certs');
const pqc = require('../src/pqc');
const fs = require('fs-extra');
const path = require('path');

describe('Post-Quantum Cryptography Tests', function() {
    const testPkiPath = path.join(__dirname, '../test-pki-pqc');
    
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

    describe('ML-KEM-1024 Key Generation', function() {
        it('should generate ML-KEM-1024 key pair via DSSSL', async function() {
            const keys = await pqc.generateMLKEM1024KeyPair();
            expect(keys).to.have.property('publicKey');
            expect(keys).to.have.property('privateKey');
            expect(keys.algorithm).to.equal('ML-KEM-1024');
        });
    });

    describe('ML-DSA-87 Key Generation', function() {
        it('should generate ML-DSA-87 key pair via DSSSL', async function() {
            const keys = await pqc.generateMLDSA87KeyPair();
            expect(keys).to.have.property('publicKey');
            expect(keys).to.have.property('privateKey');
            expect(keys.algorithm).to.equal('ML-DSA-87');
        });
    });

    describe('ML-DSA-87 Signing and Verification', function() {
        it('should sign and verify data with ML-DSA-87', async function() {
            const keys = await pqc.generateMLDSA87KeyPair();
            const testData = Buffer.from('test data for ML-DSA-87 signing');
            
            const signature = await pqc.signMLDSA87(testData, keys.privateKey);
            expect(signature).to.exist;
            expect(signature.length).to.be.greaterThan(0);
            
            const verified = await pqc.verifyMLDSA87(testData, signature, keys.publicKey);
            expect(verified).to.be.true;
        });
    });

    describe('Hybrid PQC Certificates', function() {
        it('should create certificate with hybrid PQC signatures', async function() {
            await certs.createCACert('Test CA PQC', {
                basePath: testPkiPath,
                pqc: true
            });
            
            const caPath = path.join(testPkiPath, 'test-ca-pqc/ca');
            expect(fs.existsSync(path.join(caPath, 'pqc_public.bin'))).to.be.true;
            expect(fs.existsSync(path.join(caPath, 'pqc_private.bin'))).to.be.true;
        });
    });
});
