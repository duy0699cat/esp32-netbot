#pragma once
// Public half of the release-signing key (ECDSA P-256). Firmware updates are only accepted when
// the release manifest carries a valid signature from the matching private key.
// If you fork this project, generate your own key (see docs/RELEASING.md) and replace this.
static const char OTA_PUBKEY_PEM[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ9or+sd/FigrfQu/327jQDMn6sTu\n"
  "r5ZEsPlRvFt45LqAuTZouTpkB87ZtD1sGiaoNkK/Hs1cwSgoiXEBL7cbcg==\n"
  "-----END PUBLIC KEY-----\n";
