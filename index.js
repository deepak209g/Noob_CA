var crypto = require('crypto');
var fs = require('fs');
var keypair = require('keypair');
var readlineSync = require('readline-sync');
const hash = crypto.createHash('sha256');
const verify = crypto.createVerify('RSA-SHA256');
const sign = crypto.createSign('RSA-SHA256');
const chalk = require('chalk');

function generateHash(text) {
    var hash = crypto.createHash('sha256');
    hash.update(text);
    return hash.digest('hex');
}

var Certificate = function(params) {
    this.serialNumber = params.serialNumber;
    this.algoUsed = params.algoUsed;
    this.issuerName = params.issuerName;
    this.validFrom = params.validFrom;
    this.validTo = params.validTo;
    this.issuedTo = params.issuedTo;
    this.pubKey = params.pubKey;
    if (params.signature) {
        this.signature = params.signature;
    }
}

Certificate.prototype.generateSignature = function(pkey) {
    var digest = generateHash(this.getCertBlob());
    //console.log(this.getCertBlob());
    sign.update(digest);
    const private_key = pkey;
    var signature = sign.sign(private_key, 'hex');
    return signature;
}

Certificate.prototype.saveCertToFile = function(filename) {
    fs.writeFileSync(filename, JSON.stringify(this));
};

Certificate.readCertFromFile = function(filename) {
    var data = fs.readFileSync(filename, 'utf8');
    return new Certificate(JSON.parse(data));
};

Certificate.prototype.setSignature = function(sign) {
    this.signature = sign;
};

Certificate.prototype.validateCert = function(publicKey) {
    var signature = this.signature;
    //console.log(publicKey);
    // decrypt signature to get digest
    const public_key = publicKey;
    var digest = generateHash(this.getCertBlob());
    //console.log(digest);
    //console.log(this.getCertBlob());
    verify.update(digest);
    //console.log(typeof public_key);
    //`console.log(signature);
    return verify.verify(public_key, signature, 'hex');
};

Certificate.prototype.getCertBlob = function() {
    var blob = '';
    for (var key in this) {
        if (this.hasOwnProperty(key)) {
            /* useful code here */
            if (key != 'signature') {
                blob += this[key];
            }
        }
    }
    return blob;
};

var CertAuth = function(name, cert, myKey) {
    this.name = name;
    this.mycert = cert;
    this.myPrivKey = myKey;
};

CertAuth.generateSSC = function(publickey, name) {
    var currentDate = new Date();
    var validFrom = currentDate;
    var validTo = new Date(currentDate.getTime()).setYear(parseInt(currentDate.getYear()) + 1);
    var cert = new Certificate({
        serialNumber: currentDate.getTime(),
        algoUsed: "RSA",
        issuerName: name,
        validFrom: validFrom.getTime(),
        validTo: validTo,
        issuedTo: name,
        pubKey: publickey
    });
    return cert;
};

CertAuth.prototype.generateNewCertificate = function(publickey) {
    var name = readlineSync.question('May I have your name: ');
    var currentDate = new Date();
    var validFrom = currentDate;
    var validTo = new Date(currentDate.getTime()).setYear(parseInt(currentDate.getYear()) + 1);
    var cert = new Certificate({
        serialNumber: currentDate.getTime(),
        algoUsed: "RSA",
        issuerName: this.name,
        validFrom: validFrom.getTime(),
        validTo: validTo,
        issuedTo: name,
        pubKey: publickey
    });
    return cert;
}

CertAuth.prototype.signCert = function(cert) {
    var sign = cert.generateSignature(this.myPrivKey);
    cert.setSignature(sign);
    return cert;
}

CertAuth.prototype.validateCert = function(cert) {
    return cert.validateCert(this.mycert.pubKey);
}

function Driver() {
    var noobCA;
    if (fs.existsSync("noobpriv.key")) {
        // CA exists
        //console.log("Existing CA opened");
        var mycert = Certificate.readCertFromFile("noobCAcert.cert");
        var myprivkey = readPrivateKeyFromFile("noobpriv.key");
        noobCA = new CertAuth("Noob CA", mycert, myprivkey);
    } else {
        // run first time
        //console.log("New CA opened");
        var pair = keypair();
        var noobcert = CertAuth.generateSSC(pair.public, "Noob CA");
        noobCA = new CertAuth("Noob CA", noobcert, pair.private);
        noobcert = noobCA.signCert(noobcert);
        noobCA.mycert = noobcert;
        noobcert.saveCertToFile("noobCAcert.cert");
        savePrivKeyToFile("noobpriv.key", pair.private);
    }

        var options = ['Request new Certificate', 'Validate Certificate', 'Exit'];
        var index = readlineSync.keyInSelect(options, "Select an option");
        index += 1;
        //console.log(index);
        switch (index) {
            case 1:
                var newPair = keypair();
                var newCert = noobCA.generateNewCertificate(newPair.public);
                newCert = noobCA.signCert(newCert);
                //console.log(newCert);
                newCert.saveCertToFile(newCert.issuedTo + ".cert");
                savePrivKeyToFile(newCert.issuedTo + ".key", newPair.private);
                break;
            case 2:
                var filename = readlineSync.question('Enter Certificate filename:  ');
                var cert = Certificate.readCertFromFile(filename);
                var result = noobCA.validateCert(cert);
                if (result == true) {
                    console.log(chalk.green("================="));
                    console.log(chalk.green("This is a valid certificate"));
                    console.log(chalk.green("Certificate belongs to : " + cert.issuedTo));
                    console.log(chalk.green("Certificate issued by : " + cert.issuerName));
                    console.log(chalk.green("================="));
                } else {
                    console.log("----------------");
                    console.log();
                    console.log(chalk.red("This is an invalid certificate"));
                    console.log(chalk.red("The certificate may have been tampered with"));
                    console.log(chalk.red("Do not use this certificate !!"));
                    console.log();
                    console.log("----------------");
                }
                break;
            case 3:
                //console.log("Default operation");
                return;
        }
}

function savePrivKeyToFile(fileName, privateKey) {
    fs.writeFileSync(fileName, privateKey);
}

function readPrivateKeyFromFile(filename) {
    return fs.readFileSync(filename);
}

Driver();
