let tls = require('tls');
let fs = require('fs');
// load les variables du fichier .env dans l'objet process.env
require('dotenv').config();

let portNumber = process.env.PORT;
let domain = process.env.DOMAIN;

let tlsOptions = {
	ca: fs.readFileSync('./ssl/autorite/autorite.cer'),
	cert: fs.readFileSync('./ssl/certificats/client-cert.cer'),
	key: fs.readFileSync('./ssl/certificats/client-key.pem'),
	passphrase: process.env.PRIVATE_KEY_PASSPHRASE,
	ciphers: [
        "ECDHE-RSA-AES256-SHA384",
        "DHE-RSA-AES256-SHA384",
         "HIGH",
        "!MD5",
	].join(':'),
	honorCipherOrder: true
};

let client = tls.connect(portNumber, domain, tlsOptions, function() {
	client.isPasswordValidated = false;
	// client.authorized est true si le certificat du serveur est approuve par le client.
	process.stdout.write(`Server certificate ${client.authorized ? 'authorized' : 'unauthorized'}\n`);
	client.setEncoding('utf8');

	process.stdout.write('Enter your password\n');
	process.stdin.pipe(client);
	process.stdin.resume();
});

client.on('data', function(data) {
	// si le serveur affirme que le mot de passe est OK, les messages recu s'affiche.
	if (!client.isPasswordValidated) {
		client.isPasswordValidated = data === 'valid password';
		return;
	}
	process.stdout.write(`Received: ${data}\n`);
});

client.on('end', function() {
	process.stdout.write('Connection closed\n');
	process.exit(0);
});

client.on('error', function(err) {
	process.stdout.write(err);
	process.exit(1);
});

process.on('SIGINT', function() {
	client.end(function() {
		process.stdout.write('Connection closed\n');
		process.exit(0);
	});
});