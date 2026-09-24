'use strict';

const { ClientSecretCredential, DefaultAzureCredential } = require('@azure/identity');

// Mirrors the AWS SDK's credential-chain flexibility: explicit service-principal
// credentials when supplied, otherwise fall back to DefaultAzureCredential
// (env vars, az login, managed identity).
function buildAzureCredential({ tenantId, clientId, clientSecret }) {
  if (tenantId && clientId && clientSecret) {
    return new ClientSecretCredential(tenantId, clientId, clientSecret);
  }
  return new DefaultAzureCredential();
}

module.exports = { buildAzureCredential };
