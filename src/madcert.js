#!/usr/bin/env node

const version = require('../package.json').version;

const util = require('util')
const yargs = require('yargs');
const certs = require('./certs');
const compliance = require('./compliance');

let executed = false;
const argv = yargs
    .scriptName('madcert')
    .usage('madcert <cmd>')
    .command('ca-create <name>', 'create a certificate authority', {}, async function(argv) {
        executed = true;
        try {
            await certs.createCACert(argv.name, {
                basePath: argv.path,
                commonName: argv['common-name'],
                country: argv.country,
                expired: argv.expired,
                organizations: argv.org,
                organizationalUnits: argv['org-unit'],
                validFrom: argv['valid-from'],
                validTo: argv['valid-to'],
                keyType: argv['key-type'],
                keySize: argv['key-size'],
                pqc: argv['pqc']
            });
        } catch (err) {
            console.error(`[ERROR] Failed to create CA: ${err.message}`);
            process.exit(1);
        }
    })
    .command(
        'ca-intermediate-create <name> <root_ca_name>',
        'create an intermediate certificate authority',
        {},
        async function(argv) {
            executed = true;
            try {
                await certs.createIntermediateCACert(argv.name, argv.root_ca_name, {
                    basePath: argv.path,
                    commonName: argv['common-name'],
                    country: argv.country,
                    expired: argv.expired,
                    organizations: argv.org,
                    organizationalUnits: argv['org-unit'],
                    validFrom: argv['valid-from'],
                    validTo: argv['valid-to'],
                    keyType: argv['key-type'],
                    keySize: argv['key-size'],
                    pqc: argv['pqc']
                });
            } catch (err) {
                console.error(`[ERROR] Failed to create intermediate CA: ${err.message}`);
                process.exit(1);
            }
        }
    )
    .command('ca-list', 'list certificate authorities', {}, function(argv) {
        executed = true;
        certs.listCACerts(argv.path);
    })
    .command(
        'ca-print <name>',
        'print certificate authority details',
        {},
        function(argv) {
            executed = true;
            console.log(util.inspect(certs.caCertToJSON(argv.path, argv.name, argv.properties), {showHidden: false, depth: null}));
        }
    )
    .command(
        'ca-remove <name>',
        'remove a certificate authority and all associated users and servers',
        {},
        function(argv) {
            executed = true;
            certs.removeCACert(argv.name, argv.path);
        }
    )
    .command('server-create <name> <ca_name>', 'create a server certificate', {}, async function(argv) {
        executed = true;
        try {
            await certs.createServerCert(argv.name, argv.ca_name, argv.localhost, {
            basePath: argv.path,
            commonName: argv['common-name'],
            country: argv.country,
            locality: argv.locality,
            state: argv.state,
            expired: argv.expired,
            organizations: argv.org,
            organizationalUnits: argv['org-unit'],
            password: argv.password,
            rootCaName: argv['root-ca-name'],
            subjectAltDnsNames: argv['subject-alt-dns'],
            subjectAltIpNames: argv['subject-alt-ip'],
            validFrom: argv['valid-from'],
            validTo: argv['valid-to'],
            keyType: argv['key-type'],
            keySize: argv['key-size'],
            pqc: argv['pqc']
            });
        } catch (err) {
            console.error(`[ERROR] Failed to create server certificate: ${err.message}`);
            process.exit(1);
        }
    })
    .command('server-list', 'list server certificates', {}, function(argv) {
        executed = true;
        certs.listServerCerts(argv.path);
    })
    .command(
        'server-print <name> <ca_name>',
        'print server certificate details',
        {},
        function(argv) {
            executed = true;
            console.log(util.inspect(certs.serverCertToJSON(argv.path, argv.ca_name, argv.name, argv.properties), {showHidden: false, depth: null}));
        }
    )
    .command('server-remove <name> <ca_name>', 'remove a server certificate', {}, function(argv) {
        executed = true;
        certs.removeServerCert(argv.name, argv.ca_name, argv.path);
    })
    .command('user-create <name> <ca_name>', 'create a user certificate', {}, async function(argv) {
        executed = true;
        try {
            await certs.createUserCert(argv.name, argv.ca_name, {
            basePath: argv.path,
            commonName: argv['common-name'],
            country: argv.country,
            locality: argv.locality,
            state: argv.state,
            expired: argv.expired,
            rootCaName: argv['root-ca-name'],
            organizations: argv.org,
            organizationalUnits: argv['org-unit'],
            password: argv.password,
            subjectAltEmailNames: argv['subject-alt-email'],
            validFrom: argv['valid-from'],
            validTo: argv['valid-to'],
            keyType: argv['key-type'],
            keySize: argv['key-size'],
            pqc: argv['pqc']
            });
        } catch (err) {
            console.error(`[ERROR] Failed to create user certificate: ${err.message}`);
            process.exit(1);
        }
    })
    .command('user-list', 'list user certificates', {}, function(argv) {
        executed = true;
        certs.listUserCerts(argv.path);
    })
    .command(
        'user-print <name> <ca_name>',
        'print user certificate details',
        {},
        function(argv) {
            executed = true;
            console.log(util.inspect(certs.userCertToJSON(argv.path, argv.ca_name, argv.name, argv.properties), {showHidden: false, depth: null}));
        }
    )
    .command('user-remove <name> <ca_name>', 'remove a user certificates', {}, function(argv) {
        executed = true;
        certs.removeUserCert(argv.name, argv.ca_name, argv.path);
    })
    .command(
        'create-db <ca_name>',
        'create an openssl database file from existing certs',
        {},
        function(argv) {
            executed = true;
            certs.createCertDatabase(argv.ca_name, {
                basePath: argv.path ? argv.path : undefined,
            });
        }
    )
    .command('crl-generate <ca_name>', 'generate or update Certificate Revocation List', {}, function(argv) {
        executed = true;
        try {
            const crlPem = certs.generateCRL(argv.ca_name, {
                basePath: argv.path,
                validityDays: argv['validity-days'] || 30
            });
            console.log(`CRL generated successfully for CA: ${argv.ca_name}`);
        } catch (err) {
            console.error(`[ERROR] Failed to generate CRL: ${err.message}`);
            process.exit(1);
        }
    })
    .command('cert-revoke <name> <ca_name> [reason]', 'revoke a certificate', {}, function(argv) {
        executed = true;
        try {
            // Find certificate serial number by name
            const basePath = argv.path || 'pki/';
            const certPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca_name), 
                'servers', require('./utils').normalizeName(argv.name), 'crt.pem');
            const userCertPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca_name),
                'users', require('./utils').normalizeName(argv.name), 'crt.pem');
            
            let cert;
            if (require('fs-extra').existsSync(certPath)) {
                cert = require('node-forge').pki.certificateFromPem(require('fs-extra').readFileSync(certPath, 'utf8'));
            } else if (require('fs-extra').existsSync(userCertPath)) {
                cert = require('node-forge').pki.certificateFromPem(require('fs-extra').readFileSync(userCertPath, 'utf8'));
            } else {
                throw new Error(`Certificate ${argv.name} not found for CA ${argv.ca_name}`);
            }
            
            const serial = cert.serialNumber;
            const crlPem = certs.revokeCertificate(argv.ca_name, serial, argv.reason || 'unspecified', {
                basePath: argv.path
            });
            console.log(`Certificate ${argv.name} (serial: ${serial}) revoked successfully`);
        } catch (err) {
            console.error(`[ERROR] Failed to revoke certificate: ${err.message}`);
            process.exit(1);
        }
    })
    .command('cert-status <name> <ca_name>', 'check certificate status via OCSP', {}, function(argv) {
        executed = true;
        try {
            const basePath = argv.path || 'pki/';
            const certPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca_name),
                'servers', require('./utils').normalizeName(argv.name), 'crt.pem');
            const userCertPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca_name),
                'users', require('./utils').normalizeName(argv.name), 'crt.pem');
            
            let certPathToUse;
            if (require('fs-extra').existsSync(certPath)) {
                certPathToUse = certPath;
            } else if (require('fs-extra').existsSync(userCertPath)) {
                certPathToUse = userCertPath;
            } else {
                throw new Error(`Certificate ${argv.name} not found for CA ${argv.ca_name}`);
            }
            
            const cert = require('node-forge').pki.certificateFromPem(require('fs-extra').readFileSync(certPathToUse, 'utf8'));
            const serial = cert.serialNumber;
            
            // Check CRL for revocation status
            const caPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca_name), '/ca/');
            const dbPath = require('path').join(caPath, 'index.txt');
            
            if (require('fs-extra').existsSync(dbPath)) {
                const dbContent = require('fs-extra').readFileSync(dbPath, 'utf8');
                const lines = dbContent.split('\n');
                for (const line of lines) {
                    if (line.includes(`\t${serial}\t`)) {
                        if (line.startsWith('R')) {
                            console.log(`Certificate status: REVOKED`);
                            const parts = line.split('\t');
                            console.log(`Revocation date: ${parts[2]}`);
                            return;
                        }
                    }
                }
            }
            
            // Check expiration
            const now = new Date();
            if (now > cert.validity.notAfter) {
                console.log(`Certificate status: EXPIRED`);
                console.log(`Expiration date: ${cert.validity.notAfter.toISOString()}`);
            } else if (now < cert.validity.notBefore) {
                console.log(`Certificate status: NOT_YET_VALID`);
                console.log(`Valid from: ${cert.validity.notBefore.toISOString()}`);
            } else {
                console.log(`Certificate status: VALID`);
                console.log(`Valid until: ${cert.validity.notAfter.toISOString()}`);
            }
        } catch (err) {
            console.error(`[ERROR] Failed to check certificate status: ${err.message}`);
            process.exit(1);
        }
    })
    .command('cert-renew <name> <ca_name>', 'renew an expiring certificate', {}, async function(argv) {
        executed = true;
        try {
            const basePath = argv.path || 'pki/';
            const daysBeforeExpiry = argv['days-before-expiry'] || 30;
            
            // Find certificate type (server or user)
            const serverPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca_name),
                'servers', require('./utils').normalizeName(argv.name));
            const userPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca_name),
                'users', require('./utils').normalizeName(argv.name));
            
            let certPath;
            let certType;
            if (require('fs-extra').existsSync(require('path').join(serverPath, 'crt.pem'))) {
                certPath = require('path').join(serverPath, 'crt.pem');
                certType = 'server';
            } else if (require('fs-extra').existsSync(require('path').join(userPath, 'crt.pem'))) {
                certPath = require('path').join(userPath, 'crt.pem');
                certType = 'user';
            } else {
                throw new Error(`Certificate ${argv.name} not found for CA ${argv.ca_name}`);
            }
            
            const cert = require('node-forge').pki.certificateFromPem(require('fs-extra').readFileSync(certPath, 'utf8'));
            const now = new Date();
            const expiry = cert.validity.notAfter;
            const diffDays = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
            
            if (diffDays > daysBeforeExpiry) {
                console.log(`Certificate is valid for ${diffDays} more days. Renewal not needed.`);
                return;
            }
            
            console.log(`Renewing certificate ${argv.name} (expires in ${diffDays} days)...`);
            
            // Archive old certificate
            const archiveDir = require('path').join(require('path').dirname(certPath), 'expired');
            require('fs-extra').ensureDirSync(archiveDir);
            require('fs-extra').copySync(certPath, require('path').join(archiveDir, 'crt.pem'));
            
            // Create new certificate with same options
            if (certType === 'server') {
                await certs.createServerCert(argv.name, argv.ca_name, false, {
                    basePath: argv.path,
                    rootCaName: argv['root-ca-name']
                });
            } else {
                await certs.createUserCert(argv.name, argv.ca_name, {
                    basePath: argv.path,
                    rootCaName: argv['root-ca-name']
                });
            }
            
            console.log(`Certificate ${argv.name} renewed successfully`);
        } catch (err) {
            console.error(`[ERROR] Failed to renew certificate: ${err.message}`);
            process.exit(1);
        }
    })
    .command('audit-query', 'query audit log', {}, function(argv) {
        executed = true;
        try {
            const query = {};
            if (argv.event) query.event = argv.event;
            if (argv.user) query.user = argv.user;
            if (argv.since) query.since = argv.since;
            if (argv.until) query.until = argv.until;
            
            const results = certs.queryAuditLog(query, argv.path);
            
            if (argv.format === 'json') {
                console.log(JSON.stringify(results, null, 2));
            } else {
                results.forEach(entry => {
                    console.log(`[${entry.timestamp}] ${entry.event} by ${entry.user}@${entry.hostname}`);
                    if (entry.details) {
                        console.log(`  Details: ${JSON.stringify(entry.details)}`);
                    }
                    console.log(`  Hash: ${entry.hash}`);
                    console.log('');
                });
            }
        } catch (err) {
            console.error(`[ERROR] Failed to query audit log: ${err.message}`);
            process.exit(1);
        }
    })
    .command('compliance-check [path]', 'verify CNSA 2.0 compliance', {}, function(argv) {
        executed = true;
        try {
            let report;
            
            if (argv.cert) {
                report = compliance.verifyCertificateCompliance(argv.cert);
            } else if (argv.p12) {
                report = compliance.verifyPKCS12Compliance(argv.p12);
            } else if (argv.ca) {
                const basePath = argv.path || 'pki/';
                const caPath = require('path').join(basePath, require('./utils').normalizeName(argv.ca));
                report = compliance.verifyCACompliance(caPath);
            } else {
                const basePath = argv.path || 'pki/';
                report = compliance.generateComplianceReport(basePath);
            }
            
            if (argv.format === 'json') {
                console.log(JSON.stringify(report, null, 2));
            } else {
                console.log('=== CNSA 2.0 Compliance Report ===\n');
                console.log(`Overall Status: ${report.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'}\n`);
                
                if (report.summary) {
                    console.log('Summary:');
                    console.log(`  Total CAs: ${report.summary.totalCAs}`);
                    console.log(`  Compliant CAs: ${report.summary.compliantCAs}`);
                    console.log(`  Total Certificates: ${report.summary.totalCertificates}`);
                    console.log(`  Compliant Certificates: ${report.summary.compliantCertificates}`);
                    console.log(`  Total PKCS#12 Files: ${report.summary.totalP12Files}`);
                    console.log(`  Compliant PKCS#12 Files: ${report.summary.compliantP12Files}\n`);
                }
                
                if (report.issues && report.issues.length > 0) {
                    console.log('Issues:');
                    report.issues.forEach(issue => console.log(`  - ${issue}`));
                    console.log('');
                }
                
                if (report.warnings && report.warnings.length > 0) {
                    console.log('Warnings:');
                    report.warnings.forEach(warning => console.log(`  - ${warning}`));
                    console.log('');
                }
                
                if (report.details) {
                    console.log('Details:');
                    console.log(util.inspect(report.details, { depth: null, colors: true }));
                }
            }
            
            if (argv['fail-on-non-compliant'] && !report.compliant) {
                process.exit(1);
            }
        } catch (err) {
            console.error(`[ERROR] Failed to check compliance: ${err.message}`);
            process.exit(1);
        }
    })
    .option('path', {
        alias: 'p',
        describe: 'Base path for pki.',
        default: 'pki/',
        requiresArg: true,
    })
    .option('common-name', {
        alias: 'n',
        describe: 'Common Name in the Distinguished Name.',
        requiresArg: true,
    })
    .option('country', {
        alias: 'c',
        describe: 'Country.',
        default: 'US',
        requiresArg: true,
    })
    .option('locality', {
        describe: 'Locality',
    })
    .option('state', {
        alias: 'st',
        describe: 'State',
    })
    .option('expired', {
        alias: 'e',
        describe: 'Create an expired certificate.',
        type: 'boolean',
    })
    .option('org', {
        alias: 'o',
        describe: 'Organization name. This option can be specified multiple times.',
        type: 'array',
        requiresArg: true,
    })
    .option('org-unit', {
        alias: 'u',
        describe: 'Organizational unit name. This option can be specified multiple times.',
        type: 'array',
        requiresArg: true,
    })
    .option('root-ca-name', {
        alias: 'r',
        describe: 'Root CA name.',
        requiresArg: true,
    })
    .option('localhost', {
        alias: 'l',
        describe: 'Create a localhost server certificate with subject alternative names.',
        type: 'boolean',
        default: false,
    })
    .option('password', {
        alias: 'w',
        describe: 'Create the key with the the password (defaults to "changeme").',
        type: 'string',
        default: 'changeme',
        requiresArg: true,
    })
    .option('subject-alt-dns', {
        alias: 'd',
        describe:
            'Create certificate with DNS subject alternative name. This option can be specified multiple times.',
        type: 'array',
        default: [],
        requiresArg: true,
    })
    .option('subject-alt-ip', {
        alias: 'i',
        describe:
            'Create certificate with IP subject alternative name. This option can be specified multiple times.',
        type: 'array',
        default: [],
        requiresArg: true,
    })
    .option('subject-alt-email', {
        alias: ['m', 'subject-alt-rfc822'],
        describe:
            'Create certificate with rfc822/email subject alternative name. This option can be specified multiple times.',
        type: 'array',
        default: [],
        requiresArg: true,
    })
    .option('valid-from', {
        alias: 'f',
        describe: 'Valid from date in ISO 8601 format.',
        requiresArg: true,
    })
    .option('valid-to', {
        alias: 't',
        describe: 'Valid to date in ISO 8601 format.',
        requiresArg: true,
    })
    .option('properties', {
        describe: 'Properties to filter print result. This option can be specified multiple times.',
        type: 'array',
        default: [],
        requiresArg: true,
    })
    .option('key-type', {
        alias: 'kt',
        type: 'string',
        default: 'ec',
        describe: 'Key type: "ec" (default for CNSA 2.0) or "rsa".',
    })
    .option('key-size', {
        alias: 'ks',
        type: 'number',
        describe: 'RSA key size (min 3072, default 4096).',
    })
    .option('pqc', {
        type: 'boolean',
        default: false,
        describe: 'Enable hybrid Post-Quantum Cryptography (ML-KEM-1024 + ML-DSA-87).',
    })
    .option('validity-days', {
        type: 'number',
        describe: 'CRL validity period in days (default: 30)',
        requiresArg: true,
    })
    .option('days-before-expiry', {
        type: 'number',
        describe: 'Days before expiration to trigger renewal (default: 30)',
        requiresArg: true,
    })
    .option('event', {
        type: 'string',
        describe: 'Filter audit log by event type',
        requiresArg: true,
    })
    .option('user', {
        type: 'string',
        describe: 'Filter audit log by user',
        requiresArg: true,
    })
    .option('since', {
        type: 'string',
        describe: 'Filter audit log from date (ISO 8601)',
        requiresArg: true,
    })
    .option('until', {
        type: 'string',
        describe: 'Filter audit log until date (ISO 8601)',
        requiresArg: true,
    })
    .option('format', {
        type: 'string',
        describe: 'Output format: json or human (default: human)',
        default: 'human',
        requiresArg: true,
    })
    .option('cert', {
        type: 'string',
        describe: 'Check single certificate file for compliance',
        requiresArg: true,
    })
    .option('p12', {
        type: 'string',
        describe: 'Check single PKCS#12 file for compliance',
        requiresArg: true,
    })
    .option('ca', {
        type: 'string',
        describe: 'Check entire CA for compliance',
        requiresArg: true,
    })
    .option('fail-on-non-compliant', {
        type: 'boolean',
        describe: 'Exit with error code if non-compliant items found',
        default: false,
    })
    .alias('version', 'v')
    .alias('h', 'help')
    .conflicts('expired', 'valid-to')
    .version(version)
    .help('help')
    .group('common-name', 'Creation Options:')
    .group('country', 'Creation Options:')
    .group('locality', 'Creation Options:')
    .group('state', 'Creation Options:')
    .group('expired', 'Creation Options:')
    .group('org-unit', 'Creation Options:')
    .group('org', 'Creation Options:')
    .group('root-ca-name', 'Creation Options:')
    .group('valid-from', 'Creation Options:')
    .group('valid-to', 'Creation Options:')
    .group('key-type', 'Creation Options:')
    .group('key-size', 'Creation Options:')
    .group('password', 'User Creation Options:')
    .group('subject-alt-email', 'User Creation Options:')
    .group('localhost', 'Server Creation Options:')
    .group('password', 'Server Creation Options:')
    .group('subject-alt-dns', 'Server Creation Options:')
    .group('subject-alt-ip', 'Server Creation Options:')
    .group('properties', 'Print Options:')
    .wrap(yargs.terminalWidth()).argv;

if (!executed) {
    yargs.showHelp();
}
