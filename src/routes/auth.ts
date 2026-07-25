import { Router } from "express";
import { pkceChallenge, randomString } from "../helpers/crypto.js";
import { createRemoteJWKSet, jwtVerify } from "jose";

interface TokenResponse {
    id_token: string;
    access_token: string;
    token_type: string;
    expires_in: number;
}

export const authRouter: Router = Router();

authRouter.get("/login", (req, res) => {
    const state = randomString(32);
    const nonce = randomString(32);
    const codeVerifier = randomString(32);

    req.session.state = state;
    req.session.nonce = nonce;
    req.session.codeVerifier = codeVerifier;

    const params = new URLSearchParams({
        response_type: "code",
        client_id: process.env.AUTH0_CLIENT_ID!,
        redirect_uri: process.env.AUTH0_REDIRECT_URI!,
        scope: "openid profile email",
        state,
        nonce,
        code_challenge: pkceChallenge(codeVerifier),
        code_challenge_method: "S256"
    });

    res.redirect(`https://${process.env.AUTH0_DOMAIN}/authorize?${params.toString()}`);
});

authRouter.get("/logout", (req, res) => {
  req.session.destroy(() => {
    const params = new URLSearchParams({
      client_id: process.env.AUTH0_CLIENT_ID!,
      returnTo: "http://localhost:3000",
    });
    res.redirect(`https://${process.env.AUTH0_DOMAIN}/v2/logout?${params}`);
  });
});

authRouter.get("/callback", async (req, res) => {
    const { code, state } = req.query;

    if (!state || state !== req.session.state) {
        return res.status(400).send("state inválido");
    }

    const tokenResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            grant_type: "authorization_code",
            client_id: process.env.AUTH0_CLIENT_ID!,
            client_secret: process.env.AUTH0_CLIENT_SECRET!,
            code,
            redirect_uri: process.env.AUTH0_REDIRECT_URI!,
            code_verifier: req.session.codeVerifier
        })
    });

    if (!tokenResponse.ok) {
        return res.status(400).send("Token exchange failed");
    }

    const tokenData = (await tokenResponse.json()) as TokenResponse;

    const JWKS = createRemoteJWKSet(new URL(`https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`));

    const { payload } = await jwtVerify(tokenData.id_token, JWKS, {
        issuer: `https://${process.env.AUTH0_DOMAIN}/`,
        audience: process.env.AUTH0_CLIENT_ID!
    });

    if (payload.nonce !== req.session.nonce) {
        return res.status(400).send("Invalid nonce");
    }

    req.session.user = payload;
    res.redirect("/");
})