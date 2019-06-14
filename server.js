let tls = require('tls');
let fs = require('fs');
let async = require('async');
var crypto = require('crypto');
const low = require('lowdb')
const FileSync = require('lowdb/adapters/FileSync')
require('dotenv').config();

const adapter = new FileSync('db.json');
const db = low(adapter);

// Set some defaults (required if your JSON file is empty)
db.defaults({ users: []})
  .write();

// Liste des connections de chaque client
let clients = [];

let portNumber = process.env.PORT;

let tlsOptions = {
    key: fs.readFileSync('./ssl/certificats/server-key.pem'),
    cert: fs.readFileSync('./ssl/certificats/server-cert.cer'),
    ca: fs.readFileSync('./ssl/autorite/autorite.cer'),
    passphrase: process.env.PRIVATE_KEY_PASSPHRASE,
    rejectUnauthorized: true,
    requestCert: true,
    ciphers: [
        "ECDHE-RSA-AES256-SHA256",
        "HIGH",
        "!aNULL",
        "!eNULL",
        "!EXPORT",
        "!DES",
        "!RC4",
        "!MD5",
        "!PSK",
        "!SRP",
        "!CAMELLIA"
    ].join(':'),
    honorCipherOrder: true
};

// Initialiser le serveur
tls.createServer(tlsOptions, function (connection) {
    connection.name = `${connection.remoteAddress} : ${connection.remotePort}`;
    connection.setEncoding('utf8');
    connection.isPasswordReceived = false;
    process.stdout.write(`Client ${connection.name} certificate ${connection.authorized ? 'authorized' : 'unauthorized'}\n`);

    connection.user = db.get('users')
                        .find({ username: connection.remoteAddress })
                        .value();
     
    // Gerer les messages entrant
    connection.on('data', function (data) {
        // tant que le password du client n'est pas recu et approuve les messages recu ne sont pas broadcaster.
        if (!connection.isPasswordReceived) {
            connection.isPasswordReceived = true;

            let password = data;
            if (password.indexOf('\n') != -1) {
                password = password.slice(0, -2);
            }

            // On verifie le mot de passe de l'usager s'il existe
            // sinon, on inscrit l'usager dans la db
            if(connection.user == null) {
                let salt = generateRandomSalt(10);
                let hashedPassword = hashPassword(password, salt);
                db.get('users')
                    .push({ username: connection.remoteAddress, salt: salt, password: hashedPassword})
                    .write();
            } else {
                let hashedPassword = hashPassword(password, connection.user.salt);
                if(hashedPassword !== connection.user.password) {
                    connection.end();
                    return;
                }
            }

            // Dire au client que le mot de passe est OK
            connection.write('valid password');

            // Ajouter la nouvelle connexion dans la liste de clients
            clients.push(connection);

            // Message de bienvenu au client
            connection.write(`Welcome ${connection.name}\n`);
            broadcast(`${connection.name} has joined the chat\n`, connection);
        } else {
            broadcast(`${connection.name}> ${data}`, connection);
        }
    });

    // Gerer la deconnexion d'un client
    connection.on('end', function () {
        // retirer la connexion de la liste de clients.
        clients.splice(clients.indexOf(connection), 1);
        broadcast(`${connection.name} has been disconnected\n`);
    });

    connection.on('error', function() {
        connection.destroy();
        // retirer la connexion de la liste de clients.
        clients.splice(clients.indexOf(connection), 1);
        broadcast(`${connection.name} has been disconnected\n`);
    });
    
}).listen(portNumber);

// Fonction pour faire un broadcast a tout les clients d'un message
let broadcast = function(message, sender) {
    clients.forEach(function (client) {
        // On envoie pas le message au noeud qui l'a envoye
        if (client === sender) return;
        
        if (client.isPasswordReceived) {
            client.write(message);
        }
    });

    // Log dans la console du serveur
    process.stdout.write(message)
}

process.on('SIGINT', function() {
    async.forEach(clients, function (connection, next){ 
        connection.end(function() {
            next();
        });
    }, function(err) {
        if (err)  {
            process.stdout.write(err);
            process.exit(1);
            return;
        }
        
        clients = [];
        process.exit(0);
    });
});

let generateRandomSalt = function(saltLength) {
    return crypto.randomBytes(Math.ceil(saltLength / 2))
            .toString('hex')
            .slice(0, saltLength);
};

let hashPassword = function(password, salt) {
    let hash = crypto.createHmac('sha256', salt);
    hash.update(password);
    return hash.digest('hex');
};

// Put a friendly message on the terminal of the server.
process.stdout.write(`Chat server running at port ${portNumber}\n\n`);