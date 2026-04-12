/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <nrfx_timer.h>
#include <nrfx_gpiote.h>
#include <helpers/nrfx_gppi.h>

#include <stdint.h>
#include <nrfx.h>
#include <hal/nrf_ecb.h>
#include <controller/ble_fem.h>
#include "phy_ppi.h"

/* AAR output status — resolved IRK index written by the nRF54L AAR output
 * job list.  The hardware writes exactly 2 bytes per resolved IRK; if the
 * job-list entry length exceeds that the EasyDMA silently drops the write. */
uint16_t g_nrf_aar_out_status;

/* CCM scatter/gather job lists and state */
struct sg_job_entry g_ccm_in_jl[5];
struct sg_job_entry g_ccm_out_jl[5];
uint16_t g_ccm_alen;
uint16_t g_ccm_mlen;
uint16_t g_ccm_out_alen;
uint8_t g_ccm_out_adata;   /* sink for CCM ADATA output (may be masked) */
uint8_t g_ccm_adata_in;    /* pre-masked ADATA input byte */
uint16_t g_ccm_out_mlen;  /* sink for CCM MLEN output — must not overwrite BLE LENGTH */
uint8_t *g_ccm_in_ptr;
uint8_t *g_ccm_out_ptr;
uint8_t g_ccm_decrypt;
struct nrf_ccm_data *g_ccm_data_ptr;  /* saved for deferred register setup */

/* AAR scatter/gather job lists */
struct sg_job_entry g_aar_in_jl[19];
struct sg_job_entry g_aar_out_jl[2];

/*
 * CCM hardware self-test results — readable via GDB.
 * Encrypts 1 byte (0x06) then decrypts it.  If both pass,
 * the scatter-gather setup is correct.
 */
volatile uint32_t g_ccm_test_enc_macstatus;
volatile uint32_t g_ccm_test_enc_errorstatus;
volatile uint32_t g_ccm_test_dec_macstatus;
volatile uint32_t g_ccm_test_dec_errorstatus;
volatile uint8_t  g_ccm_test_dec_plaintext;
volatile uint8_t  g_ccm_test_ct[5]; /* ciphertext(1) + MIC(4) */
volatile uint32_t g_ccm_test_ran = 0;

/* Cold-decrypt test results */
volatile uint32_t g_ccm_cold_dec_macstatus;
volatile uint32_t g_ccm_cold_dec_errorstatus;
volatile uint8_t  g_ccm_cold_dec_plaintext;
/* Global job-list test results */
volatile uint32_t g_ccm_glob_dec_macstatus;
volatile uint8_t  g_ccm_glob_dec_plaintext;
/* Post-ECB interference test results */
volatile uint32_t g_ccm_ecb_dec_macstatus;
volatile uint8_t  g_ccm_ecb_dec_plaintext;
volatile uint32_t g_ccm_ecb_dec_errorstatus;
/* Non-zero IV self-test results — the critical test that catches nonce byte-order bugs */
volatile uint8_t  g_ccm_iv_test_ct[5];     /* hardware encrypt output */
volatile uint32_t g_ccm_iv_test_enc_mac;
volatile uint32_t g_ccm_iv_test_dec_mac;
volatile uint8_t  g_ccm_iv_test_dec_pt;
volatile uint32_t g_ccm_iv_test_enc_err;
volatile uint32_t g_ccm_iv_test_dec_err;

void
ccm_selftest(void)
{
    /* Known test vector — arbitrary key, nonce, adata, 1-byte plaintext */
    static const uint8_t test_key[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };

    struct sg_job_entry in_jl[5];
    struct sg_job_entry out_jl[5];
    uint16_t alen = 1;
    uint16_t mlen_enc = 1;   /* plaintext length for encrypt */
    uint16_t mlen_dec = 5;   /* ciphertext+MIC length for decrypt */
    uint16_t out_alen = 0;
    uint16_t out_mlen = 0;
    uint8_t adata_in = 0x03; /* masked BLE header */
    uint8_t out_adata = 0;
    uint8_t plaintext = 0x06; /* LL_START_ENC_RSP */
    uint8_t enc_out[5] = {0}; /* ciphertext(1) + MIC(4) */
    uint8_t dec_out = 0;

    /* ---- Set up KEY (bswap32 + reversed word order) ---- */
    const uint32_t *kp = (const uint32_t *)test_key;
    NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
    NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
    NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
    NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);

    /* ---- Set up NONCE (IV=0, dir=1, counter=0) ---- */
    NRF_CCM->NONCE.VALUE[0] = 0;
    NRF_CCM->NONCE.VALUE[1] = 0;
    NRF_CCM->NONCE.VALUE[2] = 0x00000080; /* dir=1 */
    NRF_CCM->NONCE.VALUE[3] = 0;

    /* ==== ENCRYPT ==== */
    NRF_CCM->MODE = (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                    (CCM_MODE_DATARATE_1Mbit << CCM_MODE_DATARATE_Pos);
    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
    NRF_CCM->EVENTS_END = 0;
    NRF_CCM->EVENTS_ERROR = 0;

    mlen_enc = 1;
    in_jl[0].ptr = (uint8_t *)&alen;
    in_jl[0].attr_and_length = (11 << 24) | 2;
    in_jl[1].ptr = (uint8_t *)&mlen_enc;
    in_jl[1].attr_and_length = (12 << 24) | 2;
    in_jl[2].ptr = &adata_in;
    in_jl[2].attr_and_length = (13 << 24) | 1;
    in_jl[3].ptr = &plaintext;
    in_jl[3].attr_and_length = (14 << 24) | 1;
    in_jl[4].ptr = NULL;
    in_jl[4].attr_and_length = 0;

    out_jl[0].ptr = (uint8_t *)&out_alen;
    out_jl[0].attr_and_length = (11 << 24) | 2;
    out_jl[1].ptr = (uint8_t *)&out_mlen;
    out_jl[1].attr_and_length = (12 << 24) | 2;
    out_jl[2].ptr = &out_adata;
    out_jl[2].attr_and_length = (13 << 24) | 1;
    out_jl[3].ptr = enc_out;
    out_jl[3].attr_and_length = (14 << 24) | 5; /* CT(1) + MIC(4) */
    out_jl[4].ptr = NULL;
    out_jl[4].attr_and_length = 0;

    NRF_CCM->IN.PTR = (uint32_t)in_jl;
    NRF_CCM->OUT.PTR = (uint32_t)out_jl;
    __DSB();
    nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);

    while (NRF_CCM->EVENTS_END == 0) {}
    g_ccm_test_enc_macstatus = NRF_CCM->MACSTATUS;
    g_ccm_test_enc_errorstatus = NRF_CCM->ERRORSTATUS;
    memcpy((void *)g_ccm_test_ct, enc_out, 5);

    /* ==== DECRYPT ==== */
    NRF_CCM->MODE = CCM_MODE_MODE_FastDecryption |
                    (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                    (CCM_MODE_DATARATE_1Mbit << CCM_MODE_DATARATE_Pos);
    NRF_CCM->EVENTS_END = 0;
    NRF_CCM->EVENTS_ERROR = 0;

    /* Re-write KEY and NONCE (same values) */
    NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
    NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
    NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
    NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);
    NRF_CCM->NONCE.VALUE[0] = 0;
    NRF_CCM->NONCE.VALUE[1] = 0;
    NRF_CCM->NONCE.VALUE[2] = 0x00000080;
    NRF_CCM->NONCE.VALUE[3] = 0;

    mlen_dec = 5;
    in_jl[1].ptr = (uint8_t *)&mlen_dec;
    in_jl[3].ptr = enc_out;
    in_jl[3].attr_and_length = (14 << 24) | 5; /* CT(1) + MIC(4) */

    out_mlen = 0;
    out_jl[3].ptr = &dec_out;
    out_jl[3].attr_and_length = (14 << 24) | 1; /* plaintext(1) */

    NRF_CCM->IN.PTR = (uint32_t)in_jl;
    NRF_CCM->OUT.PTR = (uint32_t)out_jl;
    __DSB();
    nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);

    while (NRF_CCM->EVENTS_END == 0) {}
    g_ccm_test_dec_macstatus = NRF_CCM->MACSTATUS;
    g_ccm_test_dec_errorstatus = NRF_CCM->ERRORSTATUS;
    g_ccm_test_dec_plaintext = dec_out;

    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;

    /*
     * ==== COLD DECRYPT TEST ====
     * Decrypt the known ciphertext WITHOUT a preceding encrypt.
     * CCM is fully disabled/reset.  This tests whether FastDecryption
     * works from a cold state (matching the BLE RX flow).
     * Known CT+MIC from encrypt above: enc_out[0..4]
     */
    {
        struct sg_job_entry cd_in[5];
        struct sg_job_entry cd_out[5];
        uint16_t cd_alen = 1;
        uint16_t cd_mlen = 5;       /* ciphertext + MIC */
        uint16_t cd_out_alen = 0;
        uint16_t cd_out_mlen = 0;
        uint8_t cd_adata = 0x03;
        uint8_t cd_out_adata = 0;
        uint8_t cd_dec_out = 0;

        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
        NRF_CCM->MODE = CCM_MODE_MODE_FastDecryption |
                        (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                        (CCM_MODE_DATARATE_1Mbit << CCM_MODE_DATARATE_Pos);
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
        NRF_CCM->EVENTS_END = 0;
        NRF_CCM->EVENTS_ERROR = 0;

        NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
        NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
        NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
        NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);
        NRF_CCM->NONCE.VALUE[0] = 0;
        NRF_CCM->NONCE.VALUE[1] = 0;
        NRF_CCM->NONCE.VALUE[2] = 0x00000080;
        NRF_CCM->NONCE.VALUE[3] = 0;

        cd_in[0].ptr = (uint8_t *)&cd_alen;
        cd_in[0].attr_and_length = (11 << 24) | 2;
        cd_in[1].ptr = (uint8_t *)&cd_mlen;
        cd_in[1].attr_and_length = (12 << 24) | 2;
        cd_in[2].ptr = &cd_adata;
        cd_in[2].attr_and_length = (13 << 24) | 1;
        cd_in[3].ptr = enc_out;
        cd_in[3].attr_and_length = (14 << 24) | 5;
        cd_in[4].ptr = NULL;
        cd_in[4].attr_and_length = 0;

        cd_out[0].ptr = (uint8_t *)&cd_out_alen;
        cd_out[0].attr_and_length = (11 << 24) | 2;
        cd_out[1].ptr = (uint8_t *)&cd_out_mlen;
        cd_out[1].attr_and_length = (12 << 24) | 2;
        cd_out[2].ptr = &cd_out_adata;
        cd_out[2].attr_and_length = (13 << 24) | 1;
        cd_out[3].ptr = &cd_dec_out;
        cd_out[3].attr_and_length = (14 << 24) | 1;
        cd_out[4].ptr = NULL;
        cd_out[4].attr_and_length = 0;

        NRF_CCM->IN.PTR = (uint32_t)cd_in;
        NRF_CCM->OUT.PTR = (uint32_t)cd_out;
        __DSB();
        nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);

        while (NRF_CCM->EVENTS_END == 0) {}
        g_ccm_cold_dec_macstatus = NRF_CCM->MACSTATUS;
        g_ccm_cold_dec_errorstatus = NRF_CCM->ERRORSTATUS;
        g_ccm_cold_dec_plaintext = cd_dec_out;
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
    }

    /*
     * ==== GLOBAL JOB-LIST DECRYPT TEST ====
     * Same as cold decrypt but using the global g_ccm_in_jl/g_ccm_out_jl
     * arrays (same memory as BLE flow).  Tests stack vs global issue.
     */
    {
        uint16_t gl_alen = 1;
        uint16_t gl_mlen = 5;
        uint16_t gl_out_alen = 0;
        uint16_t gl_out_mlen = 0;
        uint8_t gl_adata = 0x03;
        uint8_t gl_out_adata = 0;
        uint8_t gl_dec_out = 0;

        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
        NRF_CCM->MODE = CCM_MODE_MODE_FastDecryption |
                        (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                        (CCM_MODE_DATARATE_1Mbit << CCM_MODE_DATARATE_Pos);
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
        NRF_CCM->EVENTS_END = 0;
        NRF_CCM->EVENTS_ERROR = 0;

        NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
        NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
        NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
        NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);
        NRF_CCM->NONCE.VALUE[0] = 0;
        NRF_CCM->NONCE.VALUE[1] = 0;
        NRF_CCM->NONCE.VALUE[2] = 0x00000080;
        NRF_CCM->NONCE.VALUE[3] = 0;

        g_ccm_in_jl[0].ptr = (uint8_t *)&gl_alen;
        g_ccm_in_jl[0].attr_and_length = (11 << 24) | 2;
        g_ccm_in_jl[1].ptr = (uint8_t *)&gl_mlen;
        g_ccm_in_jl[1].attr_and_length = (12 << 24) | 2;
        g_ccm_in_jl[2].ptr = &gl_adata;
        g_ccm_in_jl[2].attr_and_length = (13 << 24) | 1;
        g_ccm_in_jl[3].ptr = enc_out;
        g_ccm_in_jl[3].attr_and_length = (14 << 24) | 5;
        g_ccm_in_jl[4].ptr = NULL;
        g_ccm_in_jl[4].attr_and_length = 0;

        g_ccm_out_jl[0].ptr = (uint8_t *)&gl_out_alen;
        g_ccm_out_jl[0].attr_and_length = (11 << 24) | 2;
        g_ccm_out_jl[1].ptr = (uint8_t *)&gl_out_mlen;
        g_ccm_out_jl[1].attr_and_length = (12 << 24) | 2;
        g_ccm_out_jl[2].ptr = &gl_out_adata;
        g_ccm_out_jl[2].attr_and_length = (13 << 24) | 1;
        g_ccm_out_jl[3].ptr = &gl_dec_out;
        g_ccm_out_jl[3].attr_and_length = (14 << 24) | 1;
        g_ccm_out_jl[4].ptr = NULL;
        g_ccm_out_jl[4].attr_and_length = 0;

        NRF_CCM->IN.PTR = (uint32_t)g_ccm_in_jl;
        NRF_CCM->OUT.PTR = (uint32_t)g_ccm_out_jl;
        __DSB();
        nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);

        while (NRF_CCM->EVENTS_END == 0) {}
        g_ccm_glob_dec_macstatus = NRF_CCM->MACSTATUS;
        g_ccm_glob_dec_plaintext = gl_dec_out;
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
    }

    /*
     * ==== POST-ECB DECRYPT TEST (H_new4) ====
     * Run ECB with a DIFFERENT key (simulating LTK-based session key
     * derivation), then decrypt with CCM using the ORIGINAL test key.
     * If ECB and CCM share the internal AES engine and the key schedule
     * is cached, CCM will use the wrong key and MACSTATUS will fail.
     * This exactly mirrors the BLE flow: ECB derives SK from LTK,
     * then CCM decrypts with SK.
     */
    {
        static const uint8_t ecb_key[16] = {
            0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8,
            0xF7,0xF6,0xF5,0xF4,0xF3,0xF2,0xF1,0xF0
        };
        static const uint8_t ecb_pt[16] = {
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
            0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
        };
        uint8_t ecb_ct[16] = {0};

        struct sg_job_entry ecb_in[2];
        struct sg_job_entry ecb_out[2];

        /* Run ECB with different key */
        const uint32_t *ekp = (const uint32_t *)ecb_key;
        NRF_ECB->KEY.VALUE[0] = __builtin_bswap32(ekp[3]);
        NRF_ECB->KEY.VALUE[1] = __builtin_bswap32(ekp[2]);
        NRF_ECB->KEY.VALUE[2] = __builtin_bswap32(ekp[1]);
        NRF_ECB->KEY.VALUE[3] = __builtin_bswap32(ekp[0]);

        ecb_in[0].ptr = (uint8_t *)ecb_pt;
        ecb_in[0].attr_and_length = (11 << 24) | 16;
        ecb_in[1].ptr = NULL;
        ecb_in[1].attr_and_length = 0;
        ecb_out[0].ptr = ecb_ct;
        ecb_out[0].attr_and_length = (11 << 24) | 16;
        ecb_out[1].ptr = NULL;
        ecb_out[1].attr_and_length = 0;

        NRF_ECB->EVENTS_END = 0;
        NRF_ECB->EVENTS_ERROR = 0;
        NRF_ECB->IN.PTR = (uint32_t)ecb_in;
        NRF_ECB->OUT.PTR = (uint32_t)ecb_out;
        nrf_ecb_task_trigger(NRF_ECB, NRF_ECB_TASK_START);
        while (NRF_ECB->EVENTS_END == 0 && NRF_ECB->EVENTS_ERROR == 0) {}

        /* Now decrypt with CCM using ORIGINAL test key.
         * If AES key schedule is corrupted by ECB, this fails. */
        {
            struct sg_job_entry pe_in[5];
            struct sg_job_entry pe_out[5];
            uint16_t pe_alen = 1;
            uint16_t pe_mlen = 5;
            uint16_t pe_out_alen = 0;
            uint16_t pe_out_mlen = 0;
            uint8_t pe_adata = 0x03;
            uint8_t pe_out_adata = 0;
            uint8_t pe_dec_out = 0;

            NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
            NRF_CCM->MODE = CCM_MODE_MODE_FastDecryption |
                            (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                            (CCM_MODE_DATARATE_1Mbit << CCM_MODE_DATARATE_Pos);
            NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
            NRF_CCM->EVENTS_END = 0;
            NRF_CCM->EVENTS_ERROR = 0;

            /* Write ORIGINAL test key to CCM */
            NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
            NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
            NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
            NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);
            NRF_CCM->NONCE.VALUE[0] = 0;
            NRF_CCM->NONCE.VALUE[1] = 0;
            NRF_CCM->NONCE.VALUE[2] = 0x00000080;
            NRF_CCM->NONCE.VALUE[3] = 0;

            pe_in[0].ptr = (uint8_t *)&pe_alen;
            pe_in[0].attr_and_length = (11 << 24) | 2;
            pe_in[1].ptr = (uint8_t *)&pe_mlen;
            pe_in[1].attr_and_length = (12 << 24) | 2;
            pe_in[2].ptr = &pe_adata;
            pe_in[2].attr_and_length = (13 << 24) | 1;
            pe_in[3].ptr = enc_out; /* known CT from encrypt test */
            pe_in[3].attr_and_length = (14 << 24) | 5;
            pe_in[4].ptr = NULL;
            pe_in[4].attr_and_length = 0;

            pe_out[0].ptr = (uint8_t *)&pe_out_alen;
            pe_out[0].attr_and_length = (11 << 24) | 2;
            pe_out[1].ptr = (uint8_t *)&pe_out_mlen;
            pe_out[1].attr_and_length = (12 << 24) | 2;
            pe_out[2].ptr = &pe_out_adata;
            pe_out[2].attr_and_length = (13 << 24) | 1;
            pe_out[3].ptr = &pe_dec_out;
            pe_out[3].attr_and_length = (14 << 24) | 1;
            pe_out[4].ptr = NULL;
            pe_out[4].attr_and_length = 0;

            NRF_CCM->IN.PTR = (uint32_t)pe_in;
            NRF_CCM->OUT.PTR = (uint32_t)pe_out;
            __DSB();
            nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);

            while (NRF_CCM->EVENTS_END == 0) {}
            g_ccm_ecb_dec_macstatus = NRF_CCM->MACSTATUS;
            g_ccm_ecb_dec_errorstatus = NRF_CCM->ERRORSTATUS;
            g_ccm_ecb_dec_plaintext = pe_dec_out;
            NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
        }
    }

    /*
     * ==== NON-ZERO IV SELF-TEST ====
     * Uses IV=DEAFBABEBADCAB24 (datasheet example), dir=1, counter=0.
     * Software AES-CCM gives CT+MIC = ae aa 6b 9f 7d.
     * If hardware encrypt output differs, the nonce register encoding is wrong.
     * This is the ONE test that catches nonce byte-order bugs — all previous
     * tests used IV=0, making nonce[0..7] zero regardless of byte order.
     */
    {
        static const uint8_t iv_test_iv[8] = {
            0xDE,0xAF,0xBA,0xBE,0xBA,0xDC,0xAB,0x24
        };
        /* Expected CT+MIC from software AES-CCM: ae aa 6b 9f 7d
         * (same key/adata/pt as main test, compared in GDB postmortem) */

        struct sg_job_entry iv_in[5];
        struct sg_job_entry iv_out[5];
        uint16_t iv_alen = 1;
        uint16_t iv_mlen_enc = 1;
        uint16_t iv_mlen_dec = 5;
        uint16_t iv_out_alen = 0;
        uint16_t iv_out_mlen = 0;
        uint8_t iv_adata = 0x03;
        uint8_t iv_out_adata = 0;
        uint8_t iv_pt = 0x06;
        uint8_t iv_enc_out[5] = {0};
        uint8_t iv_dec_out = 0;

        /* Build nonce with real IV — IV bytes REVERSED per nRF54L convention */
        uint8_t nonce[16];
        int i;
        for (i = 0; i < 8; i++) {
            nonce[i] = iv_test_iv[7 - i];
        }
        nonce[8] = 0x80;  /* dir=1, counter_msb=0 */
        nonce[9] = 0; nonce[10] = 0; nonce[11] = 0; nonce[12] = 0;
        nonce[13] = 0; nonce[14] = 0; nonce[15] = 0;
        const uint32_t *nvp = (const uint32_t *)nonce;

        /* ENCRYPT with non-zero IV */
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
        NRF_CCM->MODE = (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                        (CCM_MODE_DATARATE_1Mbit << CCM_MODE_DATARATE_Pos);
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
        NRF_CCM->EVENTS_END = 0;
        NRF_CCM->EVENTS_ERROR = 0;

        NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
        NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
        NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
        NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);
        NRF_CCM->NONCE.VALUE[0] = nvp[0];
        NRF_CCM->NONCE.VALUE[1] = nvp[1];
        NRF_CCM->NONCE.VALUE[2] = nvp[2];
        NRF_CCM->NONCE.VALUE[3] = nvp[3];

        iv_in[0].ptr = (uint8_t *)&iv_alen;
        iv_in[0].attr_and_length = (11 << 24) | 2;
        iv_in[1].ptr = (uint8_t *)&iv_mlen_enc;
        iv_in[1].attr_and_length = (12 << 24) | 2;
        iv_in[2].ptr = &iv_adata;
        iv_in[2].attr_and_length = (13 << 24) | 1;
        iv_in[3].ptr = &iv_pt;
        iv_in[3].attr_and_length = (14 << 24) | 1;
        iv_in[4].ptr = NULL;
        iv_in[4].attr_and_length = 0;

        iv_out[0].ptr = (uint8_t *)&iv_out_alen;
        iv_out[0].attr_and_length = (11 << 24) | 2;
        iv_out[1].ptr = (uint8_t *)&iv_out_mlen;
        iv_out[1].attr_and_length = (12 << 24) | 2;
        iv_out[2].ptr = &iv_out_adata;
        iv_out[2].attr_and_length = (13 << 24) | 1;
        iv_out[3].ptr = iv_enc_out;
        iv_out[3].attr_and_length = (14 << 24) | 5;
        iv_out[4].ptr = NULL;
        iv_out[4].attr_and_length = 0;

        NRF_CCM->IN.PTR = (uint32_t)iv_in;
        NRF_CCM->OUT.PTR = (uint32_t)iv_out;
        __DSB();
        nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);

        while (NRF_CCM->EVENTS_END == 0) {}
        g_ccm_iv_test_enc_mac = NRF_CCM->MACSTATUS;
        g_ccm_iv_test_enc_err = NRF_CCM->ERRORSTATUS;
        memcpy((void *)g_ccm_iv_test_ct, iv_enc_out, 5);

        /* DECRYPT the hardware output (round-trip check) */
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
        NRF_CCM->MODE = CCM_MODE_MODE_FastDecryption |
                        (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                        (CCM_MODE_DATARATE_1Mbit << CCM_MODE_DATARATE_Pos);
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
        NRF_CCM->EVENTS_END = 0;
        NRF_CCM->EVENTS_ERROR = 0;

        NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
        NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
        NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
        NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);
        NRF_CCM->NONCE.VALUE[0] = nvp[0];
        NRF_CCM->NONCE.VALUE[1] = nvp[1];
        NRF_CCM->NONCE.VALUE[2] = nvp[2];
        NRF_CCM->NONCE.VALUE[3] = nvp[3];

        iv_in[1].ptr = (uint8_t *)&iv_mlen_dec;
        iv_in[3].ptr = iv_enc_out;
        iv_in[3].attr_and_length = (14 << 24) | 5;

        iv_out_mlen = 0;
        iv_out[3].ptr = &iv_dec_out;
        iv_out[3].attr_and_length = (14 << 24) | 1;

        NRF_CCM->IN.PTR = (uint32_t)iv_in;
        NRF_CCM->OUT.PTR = (uint32_t)iv_out;
        __DSB();
        nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);

        while (NRF_CCM->EVENTS_END == 0) {}
        g_ccm_iv_test_dec_mac = NRF_CCM->MACSTATUS;
        g_ccm_iv_test_dec_err = NRF_CCM->ERRORSTATUS;
        g_ccm_iv_test_dec_pt = iv_dec_out;
        NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
    }

    g_ccm_test_ran = 1;
}

/* Create PPIB links between RADIO and PERI power domain. */
#define PPIB_RADIO_PERI(_ch, _src, _dst)                  \
    NRF_PPIB11->SUBSCRIBE_SEND[_ch] = DPPI_CH_SUB(_src);  \
    NRF_PPIB21->PUBLISH_RECEIVE[_ch] = DPPI_CH_PUB(_dst); \
    NRF_DPPIC10->CHENSET |= 1 << DPPI_CH_ ## _src;        \
    NRF_DPPIC20->CHENSET |= 1 << DPPI_CH_ ## _dst;

/* Create PPIB links between RADIO and MCU power domain. */
#define PPIB_RADIO_MCU(_ch, _src, _dst)                   \
    NRF_PPIB10->SUBSCRIBE_SEND[_ch] = DPPI_CH_SUB(_src);  \
    NRF_PPIB00->PUBLISH_RECEIVE[_ch] = DPPI_CH_PUB(_dst); \
    NRF_DPPIC10->CHENSET |= 1 << DPPI_CH_ ## _src;        \
    NRF_DPPIC00->CHENSET |= 1 << DPPI_CH_ ## _dst;

/* Create PPIB links between PERI and RADIO power domain. */
#define PPIB_PERI_RADIO(_ch, _src, _dst)                  \
    NRF_PPIB21->SUBSCRIBE_SEND[_ch] = DPPI_CH_SUB(_src);  \
    NRF_PPIB11->PUBLISH_RECEIVE[_ch] = DPPI_CH_PUB(_dst); \
    NRF_DPPIC20->CHENSET |= 1 << DPPI_CH_ ## _src;        \
    NRF_DPPIC10->CHENSET |= 1 << DPPI_CH_ ## _dst;


#define PPIB_RADIO_PERI_0(_src, _dst) PPIB_RADIO_PERI(0, _src, _dst)
#define PPIB_RADIO_PERI_1(_src, _dst) PPIB_RADIO_PERI(1, _src, _dst)
#define PPIB_RADIO_PERI_2(_src, _dst) PPIB_RADIO_PERI(2, _src, _dst)
#define PPIB_RADIO_PERI_3(_src, _dst) PPIB_RADIO_PERI(3, _src, _dst)

#define PPIB_RADIO_MCU_0(_src, _dst) PPIB_RADIO_MCU(0, _src, _dst)
#define PPIB_RADIO_MCU_1(_src, _dst) PPIB_RADIO_MCU(1, _src, _dst)
#define PPIB_PERI_RADIO_4(_src, _dst) PPIB_PERI_RADIO(4, _src, _dst)

#if PHY_USE_DEBUG
void
phy_debug_init(void)
{
#if PHY_USE_DEBUG_1
    nrf_gpio_cfg_output(MYNEWT_VAL(BLE_PHY_DBG_TIME_TXRXEN_READY_PIN));
    nrf_gpiote_task_configure(NRF_GPIOTE20, PHY_GPIOTE_DEBUG_1,
                              MYNEWT_VAL(BLE_PHY_DBG_TIME_TXRXEN_READY_PIN),
                              NRF_GPIOTE_POLARITY_NONE,
                              NRF_GPIOTE_INITIAL_VALUE_LOW);
    nrf_gpiote_task_enable(NRF_GPIOTE20, PHY_GPIOTE_DEBUG_1);

    PPIB_RADIO_PERI_0(TIMER0_EVENTS_COMPARE_0, GPIOTE20_TASKS_SET_0);
    NRF_GPIOTE20->SUBSCRIBE_SET[PHY_GPIOTE_DEBUG_1] = DPPI_CH_SUB(GPIOTE20_TASKS_SET_0);

    NRF_RADIO->PUBLISH_READY = DPPI_CH_PUB(RADIO_EVENTS_READY);
    PPIB_RADIO_PERI_1(RADIO_EVENTS_READY, GPIOTE20_TASKS_CLR_0);
    NRF_GPIOTE20->SUBSCRIBE_CLR[PHY_GPIOTE_DEBUG_1] = DPPI_CH_SUB(GPIOTE20_TASKS_CLR_0);
#endif

#if PHY_USE_DEBUG_2
    nrf_gpio_cfg_output(MYNEWT_VAL(BLE_PHY_DBG_TIME_ADDRESS_END_PIN));
    nrf_gpiote_task_configure(NRF_GPIOTE20, PHY_GPIOTE_DEBUG_2,
                              MYNEWT_VAL(BLE_PHY_DBG_TIME_ADDRESS_END_PIN),
                              NRF_GPIOTE_POLARITY_NONE,
                              NRF_GPIOTE_INITIAL_VALUE_LOW);
    nrf_gpiote_task_enable(NRF_GPIOTE20, PHY_GPIOTE_DEBUG_2);

    PPIB_RADIO_PERI_2(RADIO_EVENTS_ADDRESS, GPIOTE20_TASKS_SET_1);
    NRF_GPIOTE20->SUBSCRIBE_SET[PHY_GPIOTE_DEBUG_2] = DPPI_CH_SUB(GPIOTE20_TASKS_SET_1);

    PPIB_RADIO_PERI_3(RADIO_EVENTS_PHYEND, GPIOTE20_TASKS_CLR_1);
    NRF_GPIOTE20->SUBSCRIBE_CLR[PHY_GPIOTE_DEBUG_2] = DPPI_CH_SUB(GPIOTE20_TASKS_CLR_1);
#endif
}
#endif /* PHY_USE_DEBUG */

void
phy_ppi_init(void)
{
    /* Publish events */
    NRF_TIMER0->PUBLISH_COMPARE[0] = DPPI_CH_PUB(TIMER0_EVENTS_COMPARE_0);
    NRF_TIMER0->PUBLISH_COMPARE[3] = DPPI_CH_PUB(TIMER0_EVENTS_COMPARE_3);
    NRF_RADIO->PUBLISH_PHYEND = DPPI_CH_PUB(RADIO_EVENTS_PHYEND);

    NRF_RADIO->PUBLISH_BCMATCH = DPPI_CH_PUB(RADIO_EVENTS_BCMATCH);
    NRF_RADIO->PUBLISH_ADDRESS = DPPI_CH_PUB(RADIO_EVENTS_ADDRESS);
    NRF_CPUTIME_TIMER->PUBLISH_COMPARE[0] = DPPI_CH_PUB(RTC0_EVENTS_COMPARE_0);

    /* Cross-domain RADIO -> MCU routes for CCM00 and AAR00. */
    PPIB_RADIO_MCU_0(RADIO_EVENTS_ADDRESS, CCM00_SUBSCRIBE_START);
    PPIB_RADIO_MCU_1(RADIO_EVENTS_BCMATCH, AAR00_SUBSCRIBE_START);
    /* Cross-domain PERI -> RADIO route for scheduled start trigger. */
    PPIB_PERI_RADIO_4(RTC0_EVENTS_COMPARE_0, RTC0_EVENTS_COMPARE_0);

    /* Enable channels we publish on */
    NRF_DPPIC->CHENSET = DPPI_CH_ENABLE_ALL;

    /* radio_address_to_timer0_capture1 */
    NRF_TIMER0->SUBSCRIBE_CAPTURE[1] = DPPI_CH_SUB(RADIO_EVENTS_ADDRESS);
    /* radio_end_to_timer0_capture2 */
    NRF_TIMER0->SUBSCRIBE_CAPTURE[2] = DPPI_CH_SUB(RADIO_EVENTS_PHYEND);
}

void
phy_txpower_set(int8_t dbm)
{
    uint16_t val;

    switch (dbm) {
    case 8:
        val = RADIO_TXPOWER_TXPOWER_Pos8dBm;
        break;
    case 7:
        val = RADIO_TXPOWER_TXPOWER_Pos7dBm;
        break;
    case 6:
        val = RADIO_TXPOWER_TXPOWER_Pos6dBm;
        break;
    case 5:
        val = RADIO_TXPOWER_TXPOWER_Pos5dBm;
        break;
    case 4:
        val = RADIO_TXPOWER_TXPOWER_Pos4dBm;
        break;
    case 3:
        val = RADIO_TXPOWER_TXPOWER_Pos3dBm;
        break;
    case 2:
        val = RADIO_TXPOWER_TXPOWER_Pos2dBm;
        break;
    case 1:
        val = RADIO_TXPOWER_TXPOWER_Pos1dBm;
        break;
    case 0:
        val = RADIO_TXPOWER_TXPOWER_0dBm;
        break;
    case -1:
        val = RADIO_TXPOWER_TXPOWER_Neg1dBm;
        break;
    case -2:
        val = RADIO_TXPOWER_TXPOWER_Neg2dBm;
        break;
    case -3:
        val = RADIO_TXPOWER_TXPOWER_Neg3dBm;
        break;
    case -4:
        val = RADIO_TXPOWER_TXPOWER_Neg4dBm;
        break;
    case -5:
        val = RADIO_TXPOWER_TXPOWER_Neg5dBm;
        break;
    case -6:
        val = RADIO_TXPOWER_TXPOWER_Neg6dBm;
        break;
    case -7:
        val = RADIO_TXPOWER_TXPOWER_Neg7dBm;
        break;
    case -8:
        val = RADIO_TXPOWER_TXPOWER_Neg8dBm;
        break;
    case -9:
        val = RADIO_TXPOWER_TXPOWER_Neg9dBm;
        break;
    case -10:
        val = RADIO_TXPOWER_TXPOWER_Neg10dBm;
        break;
    case -12:
        val = RADIO_TXPOWER_TXPOWER_Neg12dBm;
        break;
    case -14:
        val = RADIO_TXPOWER_TXPOWER_Neg14dBm;
        break;
    case -16:
        val = RADIO_TXPOWER_TXPOWER_Neg16dBm;
        break;
    case -18:
        val = RADIO_TXPOWER_TXPOWER_Neg18dBm;
        break;
    case -20:
        val = RADIO_TXPOWER_TXPOWER_Neg20dBm;
        break;
    case -28:
        val = RADIO_TXPOWER_TXPOWER_Neg28dBm;
        break;
    case -40:
        val = RADIO_TXPOWER_TXPOWER_Neg40dBm;
        break;
    case -46:
        val = RADIO_TXPOWER_TXPOWER_Neg46dBm;
        break;
    default:
        val = RADIO_TXPOWER_TXPOWER_0dBm;
    }

    NRF_RADIO->TXPOWER = val;
}

int8_t
phy_txpower_round(int8_t dbm)
{
    if (dbm >= (int8_t)8) {
        return (int8_t)8;
    }

    if (dbm >= (int8_t)-10) {
        return (int8_t)dbm;
    }

    if (dbm >= (int8_t)-12) {
        return (int8_t)-12;
    }

    if (dbm >= (int8_t)-14) {
        return (int8_t)-14;
    }

    if (dbm >= (int8_t)-16) {
        return (int8_t)-16;
    }

    if (dbm >= (int8_t)-18) {
        return (int8_t)-18;
    }

    if (dbm >= (int8_t)-20) {
        return (int8_t)-20;
    }

    if (dbm >= (int8_t)-28) {
        return (int8_t)-28;
    }

    if (dbm >= (int8_t)-40) {
        return (int8_t)-40;
    }

    return (int8_t)-46;
}
