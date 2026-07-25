declare module "express-session" {
    interface SessionData {
        state?: string;
        nonce?: string;
        codeVerifier?: string;
        user?: Record<string, unknown>;
    }
}
export {};
