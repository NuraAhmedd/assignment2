import express from 'express';
import bodyParser from 'body-parser';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import base64url from 'base64url';
import { hash , compare } from 'bcrypt';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { signup, signin } from './db/db.mjs';

const { urlencoded } = bodyParser;
const app = express();
const authenticators = {};  

const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));

// Registration endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    signup(username, password);

    res.send('User registered successfully');
  } catch (error) {
    res.status(500).send('Error registering new user');
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  
    const { username, password } = req.body;
    try{
    let user = await signin(username, password);
    if (!user) {
      return res.status(400).send('Invalid credentials');
    }
      res.send('Login successful');
    } catch (error) {
      res.status(500).send('Error logging in');
    }

});

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});

// Endpoint to start the registration process
app.post('/register/start', async (req, res) => {
  // Extract username from request body
  const { username } = req.body;
  console.log(username)
  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }

  // Check if user already exists
  const user = await signin(username);
  if (user) {
    return res.status(400).send({ error: 'User already exists' });
  }

  // Generate registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName: 'Future Of Authentication',
    rpID,
    userID: base64url(Buffer.from(username)),
    userName: username,
    timeout: 60000, // Timeout for the request in milliseconds
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // Store the challenge temporarily for verification in the next step
  authenticators[username] = {
    challenge: registrationOptions.challenge,
  };

  // Send registration options to the client
  return res.send(registrationOptions);
});

// Endpoint to finish the registration process
app.post('/register/finish', async (req, res) => {
  const { username, attestationResponse } = req.body;

  // Retrieve the stored challenge from the 'authenticators' object
  const expectedChallenge = authenticators[username].challenge;

  let verification;
  try {
    // Verify the registration response
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Check if verification was successful
  const { verified } = verification;
  if (verified) {
    // Prepare user data for storage
    const user = {
      devices:[{
        credentialPublicKey: base64url.encode(verification.registrationInfo.credentialPublicKey),
        credentialID: base64url.encode(verification.registrationInfo.credentialID),
        transports: attestationResponse.response.transports,
      }],
      userID: base64url(Buffer.from(username)),
      userName: username,
    };

    // Remove the temporary authenticator
    authenticators[username] = undefined;

    try {
      // Store the user in the database
      await signup(username, user);
    }
    catch (error) {
      return res.status(400).send({ error: error.message });
    }

    // Send verification result to the client
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify registration' });
  }
});



