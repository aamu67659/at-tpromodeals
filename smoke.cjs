const db = require('./db');
console.log('DB OK exports:', Object.keys(db).sort().join(','));
const idx = db.buildIpBlockIndex([
    { value: '1.2.3.4', rule: 'exact' },
    { value: '10.0.0.0/8', rule: 'cidr' },
    { value: '192.168.*.1', rule: 'wildcard' }
]);
console.log('exact hit:', db.ipMatchesIndex('1.2.3.4', idx));
console.log('cidr hit:', db.ipMatchesIndex('10.5.7.9', idx));
console.log('cidr miss:', db.ipMatchesIndex('11.0.0.1', idx));
console.log('wildcard hit:', db.ipMatchesIndex('192.168.40.1', idx));
console.log('wildcard miss:', db.ipMatchesIndex('192.168.40.2', idx));
console.log('deny:', db.ipMatchesIndex('8.8.8.8', idx));
console.log('stripSecrets:', db.stripSecrets ? 'OK' : 'MISSING');
console.log('DONE');
