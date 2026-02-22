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

echo "Done. Secrets are ready."
