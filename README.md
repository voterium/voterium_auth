# Voterium Auth Backend
An example authentication backend that could be used with Voterium

## Quickstart
**Generate Keys**
```
# NEVER SHARE YOUR PRIVATE KEY
openssl genpkey -algorithm x25519 -out key.pem

# This is your public key
openssl pkey -in key.pem -pubout -out key.pub
```

Use this public key in the backend.

**Create a .env**
See expected env vars in `.env.sample`

## Key Concepts
- JWT

## Demonstration Implementation
- Full implementations should modify the /register and /login to use appropriate SSO strategies.
- 