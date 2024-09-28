# JWT

A simple JSON Web Token (JWT) library for Deno and Node.js, partially compliant with
the [JWT specification](https://datatracker.ietf.org/doc/html/rfc7519).

## Installation

To install the JWT library, run the following command:

```bash
# deno
deno add jsr:@gz/jwt

# npm (use any of npx, yarn dlx, pnpm dlx, or bunx)
npx jsr add @gz/jwt
```

## Usage

To encode a payload, use the `encode()` function:

```ts
import { encode } from "@gz/jwt";

const payload = {userId: 123, name: "John Doe"};

const token = await encode(payload, "secret", {algorithm: "HS256"});
```

To decode a token, use the `decode()` function:

```ts
import { decode } from "@gz/jwt";

const decoded = await decode<User>(token, "secret", {algorithm: "HS256"});
```