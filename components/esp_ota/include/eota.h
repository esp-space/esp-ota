// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define EOTA_URL_BYTES 512
#define EOTA_SHA256_BYTES 32

typedef enum {
    EOTA_STATE_UNKNOWN,
    EOTA_STATE_UNTRACKED,
    EOTA_STATE_PENDING_VERIFY,
    EOTA_STATE_VALID,
    EOTA_STATE_NEW,
    EOTA_STATE_UNDEFINED,
    EOTA_STATE_INVALID,
    EOTA_STATE_ABORTED,
    EOTA_STATE_OTHER,
} eota_state_t;

typedef struct {
    /* The label is borrowed from the SDK and remains valid for the boot. */
    const char *running_partition;
    eota_state_t state;
} eota_current_t;

typedef struct {
    /* Trusted product assembly. Never populate this from an OTA request. */
    char project_name[32];
    uint16_t chip_id;
    uint32_t ota_0_address_bytes;
    uint32_t ota_1_address_bytes;
    uint32_t ota_size_bytes;
    uint32_t connect_timeout_ms;
    uint32_t read_timeout_ms;
    uint32_t idle_timeout_ms;
    uint32_t total_timeout_ms;
    /* Set only after the application has established a trusted clock. */
    bool trusted_time;
} eota_policy_t;

typedef struct {
    /* URL is borrowed until eota_prepare returns. SHA covers the signed bin. */
    const char *image_url;
    uint8_t sha256[EOTA_SHA256_BYTES];
    uint32_t image_size_bytes;
} eota_image_t;

typedef struct {
    uint8_t running_subtype;
    uint8_t boot_subtype;
    uint8_t target_subtype;
    uint32_t running_address_bytes;
    uint32_t boot_address_bytes;
    uint32_t target_address_bytes;
    uint32_t running_size_bytes;
    uint32_t boot_size_bytes;
    uint32_t target_size_bytes;
    eota_state_t running_state;
    eota_state_t target_state;
} eota_slots_t;

/* Treat this as a receipt for an already verified inactive image. The caller
 * may persist its fields, but eota_select rechecks all durable facts. */
typedef struct {
    eota_slots_t slots;
    uint8_t sha256[EOTA_SHA256_BYTES];
    uint32_t image_size_bytes;
} eota_prepared_t;

typedef enum {
    EOTA_UPDATE_OK,
    EOTA_UPDATE_UNSUPPORTED,
    EOTA_UPDATE_INVALID_REQUEST,
    EOTA_UPDATE_SLOT_UNAVAILABLE,
    EOTA_UPDATE_TOO_LARGE,
    EOTA_UPDATE_WRONG_TARGET,
    EOTA_UPDATE_DOWNLOAD_FAILED,
    EOTA_UPDATE_HASH_MISMATCH,
    EOTA_UPDATE_SIGNATURE_INVALID,
    EOTA_UPDATE_BOOT_STATE_UNKNOWN,
    EOTA_UPDATE_RESOURCE_FAILURE,
    EOTA_UPDATE_IMAGE_INVALID,
} eota_result_t;

typedef void (*eota_progress_t)(uint32_t received_bytes, uint32_t total_bytes, void *context);

/* Signed app update (C3 RSA-3072 or ESP32 ECDSA v1), HTTPS certificate bundle
 * and bootloader rollback must all be enabled in the consumer's SDK config. */
bool eota_available(void);
/* Read the actual running, selected boot and next inactive OTA slot, including
 * durable image states. It does not imply that an upgrade is safe to start. */
eota_result_t eota_observe_slots(const eota_policy_t *policy, eota_slots_t *slots);
/* Reports actual running and inactive slots before the caller persists its
 * operation receipt. prepare repeats the check before the first Flash write. */
eota_result_t eota_preflight(const eota_policy_t *policy, uint32_t image_size_bytes,
                             eota_slots_t *slots);
/* Destructively retire the inactive app after the caller has durably recorded
 * the authorized operation and serialized all app/otadata writers. The exact
 * signed running image must match expected_running_sha256, be selected and
 * VALID; expected_target_subtype prevents erasing a different OTA slot.
 * Ensures the target's first sector is erased and reads back its image magic;
 * attempts to invalidate its inactive otadata entry, then requires readback
 * to prove the target image is invalid and the running image/selector remain
 * unchanged. A partial write or failed
 * readback returns BOOT_STATE_UNKNOWN; the durable caller receipt must be
 * reconciled before another operation. This call is idempotent under that
 * receipt, but it never creates or updates the receipt itself. */
eota_result_t eota_retire_inactive(const eota_policy_t *policy,
                                   uint8_t expected_target_subtype,
                                   const uint8_t expected_running_sha256[EOTA_SHA256_BYTES]);
/* Synchronously downloads into the inactive slot and verifies its complete
 * signed bytes. It does not select a new boot slot or reboot. ESP-IDF may
 * invalidate the inactive slot's previous otadata entry at esp_ota_begin.
 * Caller owns the worker,
 * network/time preconditions, operation receipt and serialization. Progress
 * callback must neither block nor call eota_* recursively. */
eota_result_t eota_prepare(const eota_policy_t *policy, const eota_image_t *image,
                           eota_progress_t progress, void *context, eota_prepared_t *prepared);
/* Rechecks slots, full signed image digest, the current trusted project's
 * image header and SDK signature verification,
 * then selects the target boot slot. On selection failure it restores the
 * running slot's VALID state and clears an unbooted NEW target entry; any
 * uncertain durable state is reported explicitly. */
eota_result_t eota_select(const eota_policy_t *policy, const eota_prepared_t *prepared);
/* Verify the running app, require size_bytes to equal the SDK's complete signed
 * image length, then hash those bytes. Prefixes and trailing bytes are refused. */
eota_result_t eota_sha256_running(const eota_policy_t *policy, uint32_t size_bytes,
                                  uint8_t digest[EOTA_SHA256_BYTES]);
/* Verify one exact OTA app image with the SDK (including its signature), then
 * hash all signed image bytes reported by the SDK. This reports image identity,
 * not otadata/boot-selector eligibility or product authorization. The caller
 * must serialize every app/otadata writer until it has used this observation.
 * On failure size and digest are cleared. */
eota_result_t eota_sha256_verified_image(const eota_policy_t *policy, uint8_t subtype,
                                         uint32_t *image_size_bytes,
                                         uint8_t digest[EOTA_SHA256_BYTES]);
const char *eota_error(eota_result_t result);

esp_err_t eota_inspect(eota_current_t *current);
const char *eota_state_name(eota_state_t state);
/* The application first completes its local self-test and stability window.
 * The SDK rollback call may reboot before returning. */
esp_err_t eota_confirm_pending(eota_current_t *current);
esp_err_t eota_reject_pending(eota_current_t *current);
