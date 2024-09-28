import { assert, assertEquals } from "@std/assert";
import { decode, encode, type JWTPayload } from "./mod.ts";

interface User extends JWTPayload {
    userId: number;
    name: string;
}

Deno.test(async function encodeAndDecode() {
    const payload: User = { userId: 123, name: "John Doe" };
    const token = await encode(payload, "secret", { algorithm: "HS256" });
    const decoded = await decode<User>(token, "secret", { algorithm: "HS256" });
    assertEquals(decoded.userId, 123);
    assertEquals(true, true);
});

Deno.test(async function decodeFromJwtIo() {
    const token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.z8CDl8QxNFooz6YX64Axh9HvLTodJy5-9yaWOqKrm2I";
    const decoded = await decode<User>(token, "jwt.io", { algorithm: "HS256" });
    assertEquals(decoded.foo, "bar");
});

Deno.test(async function expiredToken() {
    const payload: User = {
        userId: 123,
        name: "John Doe",
        exp: Math.floor(Date.now() / 1000) - 30,
    };

    const token = await encode(payload, "secret", { algorithm: "HS256" });

    try {
        await decode<User>(token, "secret", { algorithm: "HS256" });
        assert(false);
        // deno-lint-ignore no-explicit-any
    } catch (error: any) {
        assertEquals(error.message, "Expired token");
    }
});

Deno.test(async function notBeforeToken() {
    const payload: User = {
        userId: 123,
        name: "John Doe",
        nbf: Math.floor(Date.now() / 1000) + 30,
    };

    const token = await encode(payload, "secret", { algorithm: "HS256" });

    try {
        await decode<User>(token, "secret", { algorithm: "HS256" });
        assert(false);
        // deno-lint-ignore no-explicit-any
    } catch (error: any) {
        assertEquals(
            error.message,
            "Cannot handle token with nbf in the future",
        );
    }
});

Deno.test(async function iatToken() {
    const payload: User = {
        userId: 123,
        name: "John Doe",
        iat: Math.floor(Date.now() / 1000) + 30,
    };

    const token = await encode(payload, "secret", { algorithm: "HS256" });

    try {
        await decode<User>(token, "secret", { algorithm: "HS256" });
        assert(false);
        // deno-lint-ignore no-explicit-any
    } catch (error: any) {
        assertEquals(
            error.message,
            "Cannot handle token with iat in the future",
        );
    }
});

Deno.test(async function notBeforeTokenWithLeeway() {
    const payload: User = {
        userId: 123,
        name: "John Doe",
        nbf: Math.floor(Date.now() / 1000) + 30,
    };

    const token = await encode(payload, "secret", { algorithm: "HS256" });

    const decoded = await decode<User>(token, "secret", {
        algorithm: "HS256",
        leeway: 60,
    });

    assertEquals(decoded.userId, 123);
    assertEquals(decoded.name, "John Doe");
});

// test decode with unsupported algorithm
Deno.test(async function unsupportedAlgorithm() {
    const token = await encode({ foo: "bar" }, "secret", {
        algorithm: "HS256",
    });
    try {
        await decode(token, "secret", { algorithm: "HS512" });
        assert(false);
        // deno-lint-ignore no-explicit-any
    } catch (error: any) {
        assertEquals(error.message, "Algorithm mismatch");
    }
});

// test decode with invalid token
Deno.test(async function invalidToken() {
    try {
        await decode("invalid.token", "secret", { algorithm: "HS256" });
        assert(false);
        // deno-lint-ignore no-explicit-any
    } catch (error: any) {
        assertEquals(error.message, "Invalid JWT");
    }
});

// test invalid signature
Deno.test(async function invalidSignature() {
    const token = await encode({ foo: "bar" }, "secret", {
        algorithm: "HS256",
    });
    try {
        await decode(token + "invalid", "secret", { algorithm: "HS256" });
        assert(false);
        // deno-lint-ignore no-explicit-any
    } catch (error: any) {
        assertEquals(error.message, "Invalid signature");
    }
});

// test without algorithm
Deno.test(async function noAlgorithm() {
    const token = await encode({ foo : "bar" }, "secret");
    const decoded = await decode(token, "secret");
    assertEquals(decoded.foo, "bar");
});
