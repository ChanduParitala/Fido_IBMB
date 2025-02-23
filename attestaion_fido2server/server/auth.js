const { Fido2Lib } = require('fido2-lib');
const crypto = require('crypto');
const base64url = require('base64url');
const bcrypt = require('bcrypt');

const f2l = new Fido2Lib({
    timeout: 60000,
    rpId: "192.168.1.13",
    rpName: "FidoIbmb",
    challengeSize: 32,
    attestation: "none",
    cryptoParams: [-7],
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: true,
    authenticatorUserVerification: "required"
});

const challengeStore = new Map();
const userStore = new Map();

const authController = {
    async registerInit(req, res) {
        try {
            const { email, password } = req.body;

            if (userStore.has(email)) {
                console.log("User already exists: ", email);
                return res.status(400).json({ error: 'User already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            userStore.set(email, {
                email,
                password: hashedPassword,
                credentials: []
            });
            console.log("Initiated registration for user:", email);

            //Generate the challenge
            const name = email.substring(0, email.indexOf("@"));
            console.log("generating challenge for registering user: ", email);
            const registrationOptions = await f2l.attestationOptions(
                {
                    user: {
                        id: base64url(Buffer.from(email, 'utf8')), // Needs to be a Binary
                        name: name           // Username/email
                    }
                }
            );
            challengeStore.set(email, registrationOptions.challenge);
            const challenge = Buffer.from(registrationOptions.challenge).toString('base64'); // Standard Base64
            console.log("Challenge generated for user: ", email, "\n challenge: ", challenge);
            res.json({
                ...registrationOptions,
                // challenge: base64url.encode(registrationOptions.challenge),
                challenge: challenge,
            });

        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    },

    async registerComplete(req, res) {
        try {
            const { email, attestationObject, clientDataJSON } = req.body;

            const challenge = challengeStore.get(email);
            if (!challenge) {
                return res.status(400).json({ error: 'Challenge not found' });
            }

            const attestationExpectations = {
                challenge,
                origin: "https://cert-ibmb.com",
                factor: "either"
            };

            const regResult = await f2l.attestationResult(attestationObject, clientDataJSON, attestationExpectations);

            const credentialId = base64url.encode(regResult.authnrData.get("credId"));
            const user = userStore.get(email);
            user.credentials.push({
                credentialId,
                publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
                counter: regResult.authnrData.get("counter")
            });

            challengeStore.delete(email);
            res.json({ status: 'success' });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    },

    async loginChallenge(req, res) {
        try {
            const { email } = req.body;

            const user = userStore.get(email);
            if (!user) {
                return res.status(400).json({ error: 'User not found' });
            }

            const assertionOptions = await f2l.assertionOptions();
            const allowCredentials = user.credentials.map(cred => ({
                type: 'public-key',
                id: base64url.toBuffer(cred.credentialId),
                transports: ['internal']
            }));

            challengeStore.set(email, assertionOptions.challenge);

            res.json({
                ...assertionOptions,
                challenge: base64url.encode(assertionOptions.challenge),
                allowCredentials,
                rpId: "cert-ibmb.com"
            });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    },

    async loginComplete(req, res) {
        try {
            const { email, authenticatorData, clientDataJSON, signature } = req.body;

            const user = userStore.get(email);
            const challenge = challengeStore.get(email);
            if (!user || !challenge) {
                return res.status(400).json({ error: 'Invalid request' });
            }

            const credential = user.credentials[0];

            const assertionExpectations = {
                challenge,
                origin: "https://cert-ibmb.com",
                factor: "either",
                publicKey: credential.publicKey,
                prevCounter: credential.counter,
                userHandle: email
            };

            const authnResult = await f2l.assertionResult(
                authenticatorData,
                clientDataJSON,
                signature,
                assertionExpectations
            );

            credential.counter = authnResult.authnrData.get("counter");
            challengeStore.delete(email);

            res.json({ status: 'success' });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    }
};

module.exports = authController;
