/**
 * JWT algorithm
 */
export type Algorithm = "HS256" | "HS384" | "HS512";

/**
 * JWT header
 */
export interface JWTHeader {
    alg: Algorithm;
    typ: string;
}

/**
 * JWT options
 */
export interface JWTOptions {
    algorithm?: Algorithm;
}

/**
 * JWT decode options
 */
export interface JWTDecodeOptions extends JWTOptions {
    leeway?: number;
}

/**
 * JWT payload (potentially containing custom fields and nbf/exp)
 */
export interface JWTPayload {
    iss?: string; // Issuer
    sub?: string; // Subject
    aud?: string | string[]; // Audience
    exp?: number; // Expiration time (as a UNIX timestamp)
    nbf?: number; // Not before time (as a UNIX timestamp)
    iat?: number; // Issued at time (as a UNIX timestamp)
    jti?: string; // JWT ID (a unique identifier for the token)

    // deno-lint-ignore no-explicit-any
    [key: string]: any; // Custom fields (dynamic)
}

/**
 * Mapping of algorithms to their corresponding crypto names
 */
const algorithmsMap: { [key in Algorithm]: { name: string; hash: string } } = {
    HS256: { name: "HMAC", hash: "SHA-256" },
    HS384: { name: "HMAC", hash: "SHA-384" },
    HS512: { name: "HMAC", hash: "SHA-512" },
};

/**
 * Utility to encode Base64 URL
 *
 * @param input - Input string
 */
function base64urlEncode(input: string): string {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(input);
    const base64 = btoa(String.fromCharCode(...uint8Array));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Utility to decode Base64 URL
 *
 * @param input - Input string
 */
function base64urlDecode(input: string): string {
    input = input.replace(/-/g, "+").replace(/_/g, "/");
    const decoder = new TextDecoder();
    const uint8Array = Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
    return decoder.decode(uint8Array);
}

/**
 * Utility to convert ArrayBuffer to Base64 URL
 *
 * @param buffer - ArrayBuffer
 */
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const byteArray = new Uint8Array(buffer);
    const binaryString = String.fromCharCode(...byteArray);
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * HMAC signing utility (using Deno's built-in crypto)
 *
 * @param algorithm - Algorithm
 * @param key - Secret key
 * @param message - Message to sign
 */
async function signHMAC(
    algorithm: Algorithm,
    key: string,
    message: string,
): Promise<string> {
    const algo = algorithmsMap[algorithm];
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const messageData = encoder.encode(message);

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: algo.name, hash: { name: algo.hash } },
        false,
        ["sign"],
    );

    const signature = await crypto.subtle.sign(
        algo.name,
        cryptoKey,
        messageData,
    );

    // Convert the signature (ArrayBuffer) to a Base64 URL string
    return arrayBufferToBase64Url(signature);
}

/**
 * Encode a JWT token
 *
 * @param payload - Payload to encode
 * @param secret - Secret key
 * @param options - JWT options
 *
 * @example
 * ```ts
 * const payload = { userId: 123, name: "John Doe" };
 * const token = await encode(payload, "secret", { algorithm: "HS256" });
 * ```
 */
export async function encode<T = JWTPayload>(
    payload: T,
    secret: string,
    options: JWTOptions = {},
): Promise<string> {
    const algorithm = options.algorithm || "HS256";

    // Create JWT header
    const header: JWTHeader = {
        alg: algorithm,
        typ: "JWT",
    };

    // Convert header and payload to Base64 URL-encoded JSON
    const encodedHeader = base64urlEncode(JSON.stringify(header));
    const encodedPayload = base64urlEncode(JSON.stringify(payload));

    // Create the signature part
    const message = `${encodedHeader}.${encodedPayload}`;
    const signature = await signHMAC(algorithm, secret, message);

    return `${message}.${signature}`;
}

/**
 * Decode a JWT token
 *
 * @param token - JWT token
 * @param secret - Secret key
 * @param options - JWT options
 *
 * @example
 * ```ts
 * const decoded = await decode("token", "secret", { algorithm: "HS256" });
 * ```
 */
export async function decode<T = JWTPayload>(
    token: string,
    secret: string,
    options: JWTDecodeOptions = {},
): Promise<T> {
    const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");

    if (!encodedHeader || !encodedPayload || !encodedSignature) {
        throw new Error("Invalid JWT");
    }

    // Decode the header and payload
    const header = JSON.parse(base64urlDecode(encodedHeader)) as JWTHeader;
    const payload = JSON.parse(base64urlDecode(encodedPayload));

    // Verify the algorithm
    const algorithm = options.algorithm || "HS256";
    if (header.alg !== algorithm) {
        throw new Error("Algorithm mismatch");
    }

    // Verify the valid before time
    const now = Math.floor(Date.now() / 1000);
    if (payload.nbf && payload.nbf > now + (options.leeway || 0)) {
        throw new Error("Cannot handle token with nbf in the future");
    }

    // Verify the issued at time
    if (!payload.nbf && payload.iat && payload.iat > now + (options.leeway || 0)) {
        throw new Error("Cannot handle token with iat in the future");
    }

    // Verify the expiration time
    if (payload.exp && payload.exp <= now - (options.leeway || 0)) {
        throw new Error("Expired token");
    }

    // Verify the signature
    const message = `${encodedHeader}.${encodedPayload}`;
    const signature = await signHMAC(algorithm, secret, message);

    if (encodedSignature !== signature) {
        throw new Error("Invalid signature");
    }

    return payload;
}
