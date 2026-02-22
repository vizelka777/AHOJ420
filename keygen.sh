#!/bin/bash
set -e

mkdir -p secrets

if [ ! -f secrets/oidc_private_key.pem ]; then
    echo "Generating RSA private key..."
    openssl genrsa -out secrets/oidc_private_key.pem 2048
    chmod 600 secrets/oidc_private_key.pem
else
    echo "RSA private key already exists."
fi

if [ ! -f .env ]; then
    echo "Creating .env file..."
    touch .env
fi

if ! grep -q "OIDC_CRYPTO_KEY" .env; then
    echo "Generating OIDC_CRYPTO_KEY..."
    # Generate 32 bytes hex string
    KEY=$(openssl rand -hex 32)
    echo "OIDC_CRYPTO_KEY=$KEY" >> .env
else
    echo "OIDC_CRYPTO_KEY already set in .env."
fi

if ! grep -q "OIDC_KEY_ID" .env; then
    echo "OIDC_KEY_ID=key-current-$(date +%Y%m%d)" >> .env
else
    echo "OIDC_KEY_ID already set in .env."
fi

if ! grep -q "OIDC_PREV_PRIVKEY_PATH" .env; then
    echo "OIDC_PREV_PRIVKEY_PATH=" >> .env
fi

if ! grep -q "OIDC_PREV_KEY_ID" .env; then
    echo "OIDC_PREV_KEY_ID=" >> .env
fi

echo "Done. Secrets are ready."
