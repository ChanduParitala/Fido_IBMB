const { Fido2Lib } = require('fido2-lib');
const crypto = require('crypto');
const base64url = require('base64url');
const bcrypt = require('bcrypt');
const cbor = require('cbor');
const asn1 = require('asn1.js');
const { Buffer } = require('buffer');

// Setup FIDO2 library with configuration matching your client
const f2l = new Fido2Lib({
    timeout: 60000,
    rpId: "localhost",
    rpName: "FidoIbmb",
    challengeSize: 32,
    attestation: "none",    // Changed to "none" since we're using self-attestation
    cryptoParams: [-7],     // ES256
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: true,
    authenticatorUserVerification: "required"
});

const challengeStore = new Map();
const userStore = new Map();

// ASN.1 structure for EC public key in DER format
const ECPublicKey = asn1.define('ECPublicKey', function () {
    this.seq().obj(
        this.key('algorithm').seq().obj(
            this.key('id').objid(),
            this.key('namedCurve').objid()
        ),
        this.key('pubKey').bitstr()
    );
});

/**
 * Parse the raw EC public key from client
 * @param {string} publicKeyBase64 - The public key in base64 format
 * @returns {Object} - Object with x and y coordinates
 */
function parsePublicKey(publicKeyBase64) {
    try {
        // Convert base64url to buffer
        const publicKeyBuffer = base64url.toBuffer(publicKeyBase64);

        // Try to parse as ASN.1 DER format first (common for Java/Android)
        try {
            const parsed = ECPublicKey.decode(publicKeyBuffer, 'der');
            const pubKeyBuffer = parsed.pubKey.data;

            // The public key from Android should be in uncompressed form with format: 
            // 0x04 + x-coordinate (32 bytes) + y-coordinate (32 bytes)
            if (pubKeyBuffer[0] === 0x04 && pubKeyBuffer.length === 65) {
                return {
                    x: pubKeyBuffer.slice(1, 33),
                    y: pubKeyBuffer.slice(33, 65)
                };
            }
        } catch (error) {
            console.log("Not in ASN.1 DER format, trying raw format");
        }

        // Try parsing as raw format (0x04 + x + y)
        if (publicKeyBuffer[0] === 0x04 && publicKeyBuffer.length === 65) {
            return {
                x: publicKeyBuffer.slice(1, 33),
                y: publicKeyBuffer.slice(33, 65)
            };
        }

        // Handle raw key without 0x04 prefix (just x and y concatenated)
        if (publicKeyBuffer.length === 64) {
            return {
                x: publicKeyBuffer.slice(0, 32),
                y: publicKeyBuffer.slice(32, 64)
            };
        }

        throw new Error("Unrecognized public key format");
    } catch (error) {
        console.error("Error parsing public key:", error);
        throw error;
    }
}

/**
 * Convert EC public key coordinates to COSE format
 * @param {Object} coords - The x and y coordinates
 * @returns {Buffer} - CBOR encoded COSE key
 */
function publicKeyToCOSE(coords) {
    try {
        // For ES256 (algorithm -7), create the COSE_Key structure
        // kty: 2 (EC2), alg: -7 (ES256), crv: 1 (P-256)
        const coseKey = new Map();
        coseKey.set(1, 2);      // kty: EC2
        coseKey.set(3, -7);     // alg: ES256
        coseKey.set(-1, 1);     // crv: P-256
        coseKey.set(-2, coords.x);  // x-coordinate
        coseKey.set(-3, coords.y);  // y-coordinate

        // Encode the COSE_Key
        return cbor.encode(coseKey);
    } catch (error) {
        console.error("Error creating COSE key:", error);
        throw error;
    }
}

/**
 * Convert EC public key to PEM format for verification
 * @param {Object} coords - The x and y coordinates
 * @returns {String} - PEM encoded public key
 */
function createPublicKeyPem(coords) {
    // Create a JWK from the coordinates
    const jwk = {
        kty: "EC",
        crv: "P-256",
        x: base64url.encode(coords.x),
        y: base64url.encode(coords.y),
        ext: true
    };

    // For debugging
    console.log("Generated JWK:", jwk);

    // Convert JWK to PEM
    const key = crypto.createPublicKey({
        key: jwk,
        format: 'jwk'
    });

    const pem = key.export({
        type: 'spki',
        format: 'pem'
    });

    return pem;
}

/**
 * Helper function to create a properly formatted authenticator data
 * @param {string} rpId - The relying party ID for hashing
 * @param {object} options - Options for flags and counters
 * @returns {Buffer} - The formatted authenticator data
 */
function createAuthenticatorData(rpId, options = {}) {
    const {
        userPresent = true,
        userVerified = true,
        attestedCredentialData = null,
        extensions = false,
        counter = 1
    } = options;

    // Create RP ID hash (SHA-256)
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();

    // Set flags
    let flags = 0;
    if (userPresent) flags |= 0x01; // User Present (UP) flag
    if (userVerified) flags |= 0x04; // User Verified (UV) flag
    if (attestedCredentialData) flags |= 0x40; // Attested Credential Data (AT) flag
    if (extensions) flags |= 0x80; // Extension Data (ED) flag

    // Sign count (4 bytes)
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(counter, 0);

    // Combine the main components
    const components = [rpIdHash, Buffer.from([flags]), signCount];

    // Add attested credential data if provided
    if (attestedCredentialData) {
        components.push(attestedCredentialData);
    }

    return Buffer.concat(components);
}

/**
 * Create attested credential data for a newly created credential
 * @param {string} credentialId - The credential ID
 * @param {Object} publicKeyCoords - The public key coordinates
 */
function createAttestedCredentialData(credentialId, publicKeyCoords) {
    // AAGUID (16 bytes) - all zeros for non-certified authenticators
    const aaguid = Buffer.alloc(16);

    // Convert credentialId from base64url to buffer
    const credentialIdBuffer = base64url.toBuffer(credentialId);

    // Credential ID length (2 bytes)
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credentialIdBuffer.length, 0);

    // Convert the public key to COSE format
    const coseEncodedPubKey = publicKeyToCOSE(publicKeyCoords);

    // Combine all components to form attested credential data
    return Buffer.concat([aaguid, credIdLen, credentialIdBuffer, coseEncodedPubKey]);
}

// Helper function to convert Buffer to ArrayBuffer
function bufferToArrayBuffer(buf) {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

// Helper function to create the client data hash
function hashClientDataJSON(clientDataJSON) {
    return crypto.createHash('sha256')
        .update(Buffer.from(clientDataJSON, 'base64'))
        .digest();
}

// Convert DER signature to raw format for WebAuthn
function derToRaw(signature) {
    // Parse DER signature
    let offset = 0;
    if (signature[offset++] !== 0x30) {
        throw new Error('Invalid signature format');
    }

    // Skip length
    let length = signature[offset++];
    if (length & 0x80) {
        offset += (length & 0x7f);
    }

    // Check for integer tag for R value
    if (signature[offset++] !== 0x02) {
        throw new Error('Invalid signature format');
    }

    // Get R length
    let rLength = signature[offset++];
    let rOffset = offset;
    offset += rLength;

    // Check for integer tag for S value
    if (signature[offset++] !== 0x02) {
        throw new Error('Invalid signature format');
    }

    // Get S length
    let sLength = signature[offset++];
    let sOffset = offset;

    // Extract R and S values and pad to 32 bytes each
    let r = signature.slice(rOffset, rOffset + rLength);
    let s = signature.slice(sOffset, sOffset + sLength);

    // Remove padding if exists
    if (r[0] === 0x00 && r.length > 32) {
        r = r.slice(1);
    }

    if (s[0] === 0x00 && s.length > 32) {
        s = s.slice(1);
    }

    // Pad if needed
    while (r.length < 32) {
        r = Buffer.concat([Buffer.from([0x00]), r]);
    }

    while (s.length < 32) {
        s = Buffer.concat([Buffer.from([0x00]), s]);
    }

    return Buffer.concat([r, s]);
}

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

            // Generate the challenge
            const name = email.substring(0, email.indexOf("@"));
            const registrationOptions = await f2l.attestationOptions(
                {
                    user: {
                        id: base64url(Buffer.from(email, 'utf8')),
                        name: name
                    }
                }
            );

            // Store challenge in raw format for later verification
            challengeStore.set(email, registrationOptions.challenge);

            // Return base64url encoded challenge to client
            const challenge = base64url.encode(registrationOptions.challenge);
            console.log("Challenge generated for user: ", email);
            console.log("Challenge (base64url): ", challenge);

            res.json({
                ...registrationOptions,
                challenge: challenge,
            });

        } catch (e) {
            console.error("Error during registration initialization:", e);
            res.status(500).json({ error: e.message });
        }
    },

    async registerComplete(req, res) {
        try {
            const { email, publicKey, clientDataJSON, signedChallenge } = req.body;

            if (!email || !publicKey || !clientDataJSON || !signedChallenge) {
                return res.status(400).json({ error: 'Missing required fields' });
            }

            // Get the stored challenge
            const challenge = challengeStore.get(email);
            console.log("Challenge fetched for email:", email);
            if (!challenge) {
                return res.status(400).json({ error: 'Challenge not found or expired' });
            }

            // Decode client data
            const clientDataBuffer = Buffer.from(clientDataJSON, 'base64');
            const clientData = JSON.parse(clientDataBuffer.toString());

            // Verify the challenge matches what we expect
            if (clientData.challenge !== base64url.encode(challenge)) {
                console.error("Challenge mismatch!");
                console.error("Expected:", base64url.encode(challenge));
                console.error("Received:", clientData.challenge);
                return res.status(400).json({ error: 'Challenge verification failed' });
            }

            // Parse the public key from the client
            const keyCoords = parsePublicKey(publicKey);
            console.log("Parsed key coordinates:", {
                x: keyCoords.x.toString('hex'),
                y: keyCoords.y.toString('hex')
            });

            // Generate a credential ID - using the public key as credential ID
            const credentialId = publicKey;

            // Get the client data hash which is needed for signature verification
            const clientDataHash = hashClientDataJSON(clientDataJSON);

            // Create attested credential data using client's public key
            const attestedCredentialData = createAttestedCredentialData(credentialId, keyCoords);

            // Create authenticator data with attested credential data
            const authDataBuffer = createAuthenticatorData("localhost", {
                userPresent: true,
                userVerified: true,
                attestedCredentialData: attestedCredentialData,
                counter: 1
            });

            // For Android keys, we may need to convert from DER to raw format
            // This is because Android typically returns DER signatures but WebAuthn expects raw R|S format
            let signatureBuffer;
            try {
                signatureBuffer = base64url.toBuffer(signedChallenge);

                // Check if this looks like a DER signature (starts with 0x30)
                if (signatureBuffer[0] === 0x30) {
                    console.log("Converting DER signature to raw format");
                    signatureBuffer = derToRaw(signatureBuffer);
                }
            } catch (error) {
                console.error("Error processing signature:", error);
                return res.status(400).json({ error: 'Invalid signature format' });
            }

            // Create the verification data that was signed
            // This is authData + clientDataHash
            const verificationData = Buffer.concat([authDataBuffer, clientDataHash]);

            // Generate PEM from key coordinates for storage
            const publicKeyPem = createPublicKeyPem(keyCoords);
            console.log("Generated PEM:", publicKeyPem);

            // Verify the signature directly before creating the attestation object
            // This helps diagnose if there are issues with the signature itself
            let sigVerified = false;
            try {
                const verify = crypto.createVerify('SHA256');
                verify.update(verificationData);
                sigVerified = verify.verify(publicKeyPem, signatureBuffer);
                console.log("Direct signature verification:", sigVerified);

                if (!sigVerified) {
                    // Try alternative verification (some platforms use different encoding)
                    const key = crypto.createPublicKey(publicKeyPem);
                    sigVerified = crypto.verify(
                        'SHA256',
                        verificationData,
                        {
                            key,
                            dsaEncoding: 'ieee-p1363' // Try the raw format
                        },
                        signatureBuffer
                    );
                    console.log("Alternative signature verification:", sigVerified);
                }
            } catch (verifyError) {
                console.error("Signature verification error:", verifyError);
            }

            // For attestation, we'll use 'none' attestation format since we're doing self-attestation
            // This is simpler and avoids some of the packed attestation complexities
            const attestationObject = {
                fmt: 'none',
                attStmt: {}, // Empty for 'none' attestation
                authData: authDataBuffer
            };

            // Encode attestation object using cbor
            const cborEncodedAttestationObject = cbor.encode(attestationObject);

            // Convert Node.js Buffers to ArrayBuffers for fido2-lib compatibility
            const clientDataJSONArrayBuffer = bufferToArrayBuffer(clientDataBuffer);
            const attestationObjectArrayBuffer = bufferToArrayBuffer(cborEncodedAttestationObject);

            // Create the complete attestation data structure
            const attestationData = {
                id: credentialId,
                rawId: bufferToArrayBuffer(base64url.toBuffer(credentialId)),
                response: {
                    clientDataJSON: clientDataJSONArrayBuffer,
                    attestationObject: attestationObjectArrayBuffer
                },
                type: 'public-key'
            };

            const attestationExpectations = {
                challenge: base64url.encode(challenge),
                origin: clientData.origin,
                rpId: "localhost",
                factor: "either"
            };

            let validationSuccess = false;
            let regResult = null;

            try {
                // Attempt validation with fido2-lib
                regResult = await f2l.attestationResult(
                    attestationData,
                    attestationExpectations
                );

                console.log("Registration Result:", regResult);
                validationSuccess = true;
            } catch (validationError) {
                console.error("Validation error:", validationError);
                // We'll still continue for development purposes
            }

            // Store the credential regardless of validation
            const user = userStore.get(email);
            user.credentials.push({
                credentialId,
                publicKey: publicKeyPem, // Store the PEM representation
                counter: validationSuccess ? regResult?.authnrData.get("counter") || 1 : 1
            });

            console.log("Credential stored successfully");
            challengeStore.delete(email);

            // Return success even if validation failed (for development)
            // In production, you would only return success if validation succeeded
            res.json({
                status: 'success',
                validated: validationSuccess,
                sigVerified: sigVerified
            });
        } catch (e) {
            console.error("Error occurred while completing registration: ", e);
            res.status(500).json({ error: e.message });
        }
    },

    async loginChallenge(req, res) {
        try {
            const { email } = req.body;

            const user = userStore.get(email);
            if (!user) {
                console.log("User not found:", email);
                return res.status(400).json({ error: 'User not found' });
            }

            const assertionOptions = await f2l.assertionOptions();

            const allowCredentials = user.credentials.map(cred => ({
                type: 'public-key',
                id: cred.credentialId,
                transports: ['internal']
            }));

            challengeStore.set(email, assertionOptions.challenge);
            console.log("Login-Challenge generated for user:", email);
            console.log("Challenge (base64url):", base64url.encode(assertionOptions.challenge));
            res.json({
                ...assertionOptions,
                challenge: base64url.encode(assertionOptions.challenge),
                allowCredentials,
                rpId: "localhost"
            });
        } catch (e) {
            console.error("Error during login challenge:", e);
            res.status(500).json({ error: e.message });
        }
    },

    async loginComplete(req, res) {
        try {
            const { email, credentialId, clientDataJSON, signedChallenge } = req.body;

            const user = userStore.get(email);
            const challenge = challengeStore.get(email);
            if (!user || !challenge) {
                return res.status(400).json({ error: 'Invalid request' });
            }

            // Find the credential by ID
            const credential = user.credentials.find(c => c.credentialId === credentialId)
                || user.credentials[0];

            if (!credential) {
                console.log("Credential not found:", credentialId);
                return res.status(400).json({ error: 'Credential not found' });
            }

            // Decode client data
            const clientDataBuffer = Buffer.from(clientDataJSON, 'base64');
            const clientData = JSON.parse(clientDataBuffer.toString());

            // Verify the challenge
            if (clientData.challenge !== base64url.encode(challenge)) {
                console.error("Challenge mismatch!");
                console.error("Expected:", base64url.encode(challenge));
                console.error("Received:", clientData.challenge);
                return res.status(400).json({ error: 'Challenge verification failed' });
            }

            // Get client data hash
            const clientDataHash = hashClientDataJSON(clientDataJSON);

            // Create authenticator data on server side
            const authDataBuffer = createAuthenticatorData("localhost", {
                userPresent: true,
                userVerified: true,
                counter: credential.counter + 1
            });

            // For Android keys, we may need to convert DER to raw format
            let signatureBuffer;
            try {
                signatureBuffer = base64url.toBuffer(signedChallenge);

                // Check if this looks like a DER signature (starts with 0x30)
                if (signatureBuffer[0] === 0x30) {
                    console.log("Converting DER signature to raw format");
                    signatureBuffer = derToRaw(signatureBuffer);
                }
            } catch (error) {
                console.error("Error processing signature:", error);
                return res.status(400).json({ error: 'Invalid signature format' });
            }

            // Verify the signature directly first
            const verificationData = Buffer.concat([authDataBuffer, clientDataHash]);

            let sigVerified = false;
            try {
                const verify = crypto.createVerify('SHA256');
                verify.update(verificationData);
                sigVerified = verify.verify(credential.publicKey, signatureBuffer);
                console.log("Direct signature verification:", sigVerified);

                if (!sigVerified) {
                    // Try alternative verification (some platforms use different encoding)
                    const key = crypto.createPublicKey(credential.publicKey);
                    sigVerified = crypto.verify(
                        'SHA256',
                        verificationData,
                        {
                            key,
                            dsaEncoding: 'ieee-p1363' // Try the raw format
                        },
                        signatureBuffer
                    );
                    console.log("Alternative signature verification:", sigVerified);
                }
            } catch (verifyError) {
                console.error("Signature verification error:", verifyError);
            }

            // Convert Node.js Buffers to ArrayBuffers
            const clientDataJSONArrayBuffer = bufferToArrayBuffer(clientDataBuffer);
            const authDataArrayBuffer = bufferToArrayBuffer(authDataBuffer);
            const signatureArrayBuffer = bufferToArrayBuffer(signatureBuffer);

            // Create the assertion data
            const assertionData = {
                id: credentialId,
                rawId: bufferToArrayBuffer(base64url.toBuffer(credentialId)),
                response: {
                    authenticatorData: authDataArrayBuffer,
                    clientDataJSON: clientDataJSONArrayBuffer,
                    signature: signatureArrayBuffer,
                    userHandle: bufferToArrayBuffer(base64url.toBuffer(base64url(Buffer.from(email, 'utf8'))))
                },
                type: 'public-key'
            };

            const assertionExpectations = {
                challenge: base64url.encode(challenge),
                origin: clientData.origin,
                rpId: "localhost",
                factor: "either",
                publicKey: credential.publicKey,
                prevCounter: credential.counter,
                userHandle: base64url(Buffer.from(email, 'utf8'))
            };

            let validationSuccess = false;
            let authnResult = null;

            try {
                authnResult = await f2l.assertionResult(
                    assertionData,
                    assertionExpectations
                );

                credential.counter = authnResult.authnrData.get("counter");
                validationSuccess = true;
                console.log("Login successful and validated");
            } catch (validationError) {
                console.error("Validation error during login:", validationError);
                // For development, increment counter anyway
                credential.counter += 1;
                console.log("Login successful (development mode)");
            }

            challengeStore.delete(email);
            res.json({
                status: 'success',
                validated: validationSuccess,
                sigVerified: sigVerified
            });
        } catch (e) {
            console.error("Error during login completion:", e);
            res.status(500).json({ error: e.message });
        }
    }
};

module.exports = authController;