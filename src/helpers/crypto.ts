import { randomBytes, createHash } from "node:crypto";

export const randomString = (length: number): string => {
  return randomBytes(length).toString("base64url");
}

export const pkceChallenge = (codeVerifier: string): string => {
    return createHash("sha256").update(codeVerifier).digest("base64url");
}