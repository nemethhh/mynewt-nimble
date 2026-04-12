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

#ifndef H_PHY_HW_
#define H_PHY_HW_

#include <string.h>
#include "syscfg/syscfg.h"
#include "os/os_cputime.h"
#include <hal/nrf_ccm.h>
#include <hal/nrf_timer.h>

struct nrf_ccm_data {
    uint8_t key[16];
    uint64_t pkt_counter;
    uint8_t dir_bit;
    uint8_t iv[8];
} __attribute__((packed));

/*
 * Scatter/gather DMA job list entry — shared by AAR, CCM, ECB.
 * attr_and_length: attr[31:24] | length[23:0]
 */
struct sg_job_entry {
    uint8_t *ptr;
    uint32_t attr_and_length;
};

#define AAR_ATTR_HASH  11
#define AAR_ATTR_PRAND 12
#define AAR_ATTR_IRK   13

/*
 * AAR output status — resolved IRK index written here by the output job list.
 * The nRF54L AAR EasyDMA writes exactly 2 bytes per resolved IRK; if the
 * job-list entry length exceeds 2 the write is silently dropped.
 */
extern uint16_t g_nrf_aar_out_status;
extern uint8_t g_nrf_num_irks;

#define NRF_TIMER0 NRF_TIMER10
#define NRF_DPPIC  NRF_DPPIC10
#define NRF_RTC0   NRF_RTC10
#define NRF_AAR    NRF_AAR00
#define NRF_CCM    NRF_CCM00
#define NRF_ECB    NRF_ECB00
#define NRF_GPIOTE NRF_GPIOTE20

#if MYNEWT_VAL(OS_CPUTIME_TIMER_NUM) == 0
#define NRF_CPUTIME_TIMER NRF_TIMER20
#elif MYNEWT_VAL(OS_CPUTIME_TIMER_NUM) == 1
#define NRF_CPUTIME_TIMER NRF_TIMER21
#elif MYNEWT_VAL(OS_CPUTIME_TIMER_NUM) == 2
#define NRF_CPUTIME_TIMER NRF_TIMER22
#elif MYNEWT_VAL(OS_CPUTIME_TIMER_NUM) == 3
#define NRF_CPUTIME_TIMER NRF_TIMER23
#elif MYNEWT_VAL(OS_CPUTIME_TIMER_NUM) == 4
#define NRF_CPUTIME_TIMER NRF_TIMER24
#else
#error Unsupported OS_CPUTIME_TIMER_NUM for nRF54L PHY
#endif

#define RADIO_IRQn                  RADIO_0_IRQn
#define RADIO_INTENSET_ADDRESS_Msk  RADIO_INTENSET00_ADDRESS_Msk
#define RADIO_INTENCLR_ADDRESS_Msk  RADIO_INTENCLR00_ADDRESS_Msk
#define RADIO_INTENSET_DISABLED_Msk RADIO_INTENSET00_DISABLED_Msk
#define RADIO_INTENCLR_DISABLED_Msk RADIO_INTENCLR00_DISABLED_Msk

#define NRF_RADIO_INTENSET NRF_RADIO->INTENSET00

/* To disable all radio interrupts */
#define NRF_RADIO_IRQ_MASK_ALL                                                \
    (RADIO_INTENSET00_READY_Msk | RADIO_INTENSET00_ADDRESS_Msk |              \
     RADIO_INTENSET00_PAYLOAD_Msk | RADIO_INTENSET00_PHYEND_Msk |             \
     RADIO_INTENSET00_DISABLED_Msk | RADIO_INTENSET00_DEVMATCH_Msk |          \
     RADIO_INTENSET00_DEVMISS_Msk | RADIO_INTENSET00_BCMATCH_Msk |            \
     RADIO_INTENSET00_CRCOK_Msk | RADIO_INTENSET00_CRCERROR_Msk)

/*
 * nRF54L AAR has no STATUS register for the resolved IRK index.
 * The resolved index is written to the output job list buffer (2 bytes LE).
 */
static inline uint32_t
phy_hw_aar_get_resolved_index(void)
{
    if (NRF_AAR->OUT.AMOUNT >= sizeof(g_nrf_aar_out_status)) {
        return g_nrf_aar_out_status;
    }
    return 0;
}
#define NRF_AAR_STATUS phy_hw_aar_get_resolved_index()

static inline void
phy_hw_aar_resolv_enable(void)
{
    /* IRK scan count comes from the input job list; stop after first match. */
    NRF_AAR->MAXRESOLVED = 1;
}

static inline void
phy_hw_aar_resolv_disable(void)
{
    NRF_AAR->MAXRESOLVED = 0;
}

#define CCM_MODE_DATARATE_125Kbps CCM_MODE_DATARATE_125Kbit
#define CCM_MODE_DATARATE_500Kbps CCM_MODE_DATARATE_500Kbit

#define NRF_CCM_STATUS     NRF_CCM->MACSTATUS
#define NRF_CCM_EVENTS_END NRF_CCM->EVENTS_END

#define CCM_ATTR_ALEN  11
#define CCM_ATTR_MLEN  12
#define CCM_ATTR_ADATA 13
#define CCM_ATTR_MDATA 14

uint32_t ble_phy_get_ccm_datarate(void);

/*
 * CCM scatter/gather job lists and state.
 * Input:  [Alen][Mlen][Adata][Mdata][END] — 5 entries
 * Output: [Alen][Mlen][Adata][Mdata][END] — 5 entries
 * Both lists need ALEN+MLEN per datasheet Figs. 45-46.
 * Defined in nrf54l/phy.c.
 */
extern struct sg_job_entry g_ccm_in_jl[5];
extern struct sg_job_entry g_ccm_out_jl[5];
extern uint16_t g_ccm_alen;
extern uint16_t g_ccm_mlen;
extern uint16_t g_ccm_out_alen;
extern uint8_t g_ccm_out_adata;
extern uint8_t g_ccm_adata_in;
extern uint16_t g_ccm_out_mlen;
extern uint8_t *g_ccm_in_ptr;
extern uint8_t *g_ccm_out_ptr;
extern uint8_t g_ccm_decrypt;
extern struct nrf_ccm_data *g_ccm_data_ptr; /* saved for deferred register setup */
extern volatile uint8_t g_phy_tx_nonce8; /* actual nonce[8] written to CCM for TX */
extern volatile uint8_t g_phy_tx_enc_captured; /* 1 = first TX packet captures frozen */
extern volatile uint32_t g_phy_tx_enc_key[4]; /* KEY.VALUE as written for first TX pkt */
extern volatile uint32_t g_phy_tx_enc_nonce[4]; /* NONCE.VALUE words for first TX pkt */
extern volatile uint8_t g_phy_tx_enc_iv_bytes[8]; /* raw iv bytes for first TX pkt */

/* P0 MIC debug: capture KEY/NONCE/counter values (write-only registers) */
extern volatile uint32_t g_phy_rx_enc_nonce[4];
extern volatile uint32_t g_phy_rx_enc_key[4];
extern volatile uint64_t g_phy_rx_enc_pkt_counter;
extern volatile uint8_t g_phy_rx_enc_dir_bit;
extern volatile uint8_t g_phy_rx_enc_iv[8];
extern volatile uint8_t g_phy_rx_enc_in[8];
extern volatile uint32_t g_phy_rx_enc_mode;
extern volatile uint32_t g_phy_rx_enc_enable;
extern volatile uint8_t g_phy_rx_enc_captured;
extern volatile uint8_t g_phy_rx_enc_in_at_start[8];
extern volatile uint32_t g_phy_rx_enc_radio_state;
/* Job list state at START time (before TX path overwrites) */
extern volatile uint16_t g_phy_rx_enc_alen_at_start;
extern volatile uint16_t g_phy_rx_enc_mlen_at_start;
extern volatile uint32_t g_phy_rx_enc_mdata_attr_at_start;
extern volatile uint32_t g_phy_rx_enc_mdata_ptr_at_start;
extern volatile uint8_t g_phy_rx_enc_adata_at_start;
extern volatile uint32_t g_phy_rx_enc_adatamask_at_start;
extern volatile uint32_t g_phy_rx_enc_subscribe_start;
/* Live replay test: re-decrypt same data immediately after first MIC failure */
extern volatile uint32_t g_phy_rx_enc_replay_macstatus;
extern volatile uint8_t g_phy_rx_enc_replay_pt;
extern volatile uint32_t g_phy_rx_enc_replay_errorstatus;

/*
 * nRF54L KEY.VALUE byte order is reversed vs nRF52/nRF53.
 * KEY.VALUE[0] gets the last 4 bytes of the key (word-reversed + byte-swapped).
 */
static inline void
phy_hw_ccm_set_key(const uint8_t *key)
{
    const uint32_t *kp = (const uint32_t *)key;
    uint32_t k0 = __builtin_bswap32(kp[3]);
    uint32_t k1 = __builtin_bswap32(kp[2]);
    uint32_t k2 = __builtin_bswap32(kp[1]);
    uint32_t k3 = __builtin_bswap32(kp[0]);

    /* Capture computed values before writing to write-only registers */
    if (g_ccm_decrypt && !g_phy_rx_enc_captured) {
        g_phy_rx_enc_key[0] = k0;
        g_phy_rx_enc_key[1] = k1;
        g_phy_rx_enc_key[2] = k2;
        g_phy_rx_enc_key[3] = k3;
    }
    if (!g_ccm_decrypt && !g_phy_tx_enc_captured) {
        g_phy_tx_enc_key[0] = k0;
        g_phy_tx_enc_key[1] = k1;
        g_phy_tx_enc_key[2] = k2;
        g_phy_tx_enc_key[3] = k3;
    }

    NRF_CCM->KEY.VALUE[0] = k0;
    NRF_CCM->KEY.VALUE[1] = k1;
    NRF_CCM->KEY.VALUE[2] = k2;
    NRF_CCM->KEY.VALUE[3] = k3;
}

/*
 * Build BLE CCM nonce and write to NONCE.VALUE[0..3].
 *
 * nRF54L stores the nonce in reversed byte order vs nRF52/53.
 * Standard BLE nonce (13 bytes): counter(5) | dir<<7|counter_msb | IV(8)
 * nRF54L register layout:        IV(8) | dir<<7|counter_msb(1) | counter(4,BE)
 *
 * The reversed nonce is stored directly as LE words (no bswap).
 * See datasheet v0.8, Section 8.4.2, page 234 — NONCE.VALUE example.
 *
 * NOTE: KEY and NONCE use DIFFERENT register conventions despite both
 * being described as "reversed byte order".  KEY uses bswap32 + reversed
 * word order; NONCE uses manually reversed bytes stored as plain LE words.
 * Verified against datasheet NONCE example (IV=DEAFBABEBADCAB24, dir=1, ctr=1).
 */
static inline void
phy_hw_ccm_set_nonce(struct nrf_ccm_data *ccm_data)
{
    uint8_t nonce[16];
    const uint32_t *np;

    /* Capture raw ccm_data fields for P0 MIC debug — first packet only */
    if (g_ccm_decrypt && !g_phy_rx_enc_captured) {
        g_phy_rx_enc_pkt_counter = ccm_data->pkt_counter;
        g_phy_rx_enc_dir_bit = ccm_data->dir_bit;
        memcpy((void *)g_phy_rx_enc_iv, ccm_data->iv, 8);
    }
    if (!g_ccm_decrypt && !g_phy_tx_enc_captured) {
        memcpy((void *)g_phy_tx_enc_iv_bytes, ccm_data->iv, 8);
    }

    /*
     * IV bytes must be reversed — the nRF54L nonce register stores the
     * entire 13-byte BLE nonce in reversed byte order, packed as LE words.
     * The counter and dir fields are already in the correct (reversed =
     * big-endian) order below; the IV must also be byte-reversed.
     */
    nonce[0] = ccm_data->iv[7];
    nonce[1] = ccm_data->iv[6];
    nonce[2] = ccm_data->iv[5];
    nonce[3] = ccm_data->iv[4];
    nonce[4] = ccm_data->iv[3];
    nonce[5] = ccm_data->iv[2];
    nonce[6] = ccm_data->iv[1];
    nonce[7] = ccm_data->iv[0];
    /*
     * The controller already passes the BLE packet direction bit in the
     * convention used by the other NimBLE PHY drivers:
     *   - TX uses CONN_IS_CENTRAL(connsm)
     *   - RX uses !CONN_IS_CENTRAL(connsm)
     *
     * The nRF54L datasheet documents a plain nonce direction bit and the
     * working upstream drivers use the controller-provided value directly, so
     * do not apply any nRF54L-specific inversion here.
     */
    nonce[8] = (ccm_data->dir_bit & 1) << 7 | ((ccm_data->pkt_counter >> 32) & 0x7F);
    if (!g_ccm_decrypt) {
        g_phy_tx_nonce8 = nonce[8];
    }
    nonce[9] = (ccm_data->pkt_counter >> 24) & 0xFF;
    nonce[10] = (ccm_data->pkt_counter >> 16) & 0xFF;
    nonce[11] = (ccm_data->pkt_counter >> 8) & 0xFF;
    nonce[12] = ccm_data->pkt_counter & 0xFF;
    nonce[13] = 0;
    nonce[14] = 0;
    nonce[15] = 0;

    np = (const uint32_t *)nonce;

    /* Capture computed nonce values before writing — first pkt only */
    if (g_ccm_decrypt && !g_phy_rx_enc_captured) {
        g_phy_rx_enc_nonce[0] = np[0];
        g_phy_rx_enc_nonce[1] = np[1];
        g_phy_rx_enc_nonce[2] = np[2];
        g_phy_rx_enc_nonce[3] = np[3];
    }
    if (!g_ccm_decrypt && !g_phy_tx_enc_captured) {
        g_phy_tx_enc_nonce[0] = np[0];
        g_phy_tx_enc_nonce[1] = np[1];
        g_phy_tx_enc_nonce[2] = np[2];
        g_phy_tx_enc_nonce[3] = np[3];
        g_phy_tx_enc_captured = 1;
    }

    NRF_CCM->NONCE.VALUE[0] = np[0];
    NRF_CCM->NONCE.VALUE[1] = np[1];
    NRF_CCM->NONCE.VALUE[2] = np[2];
    NRF_CCM->NONCE.VALUE[3] = np[3];
}

/*
 * Build CCM scatter/gather job lists for BLE packet format.
 * BLE RADIO packet in RAM: [S0=hdr][LEN][S1=0][payload...][MIC if encrypted]
 * CCM Adata = S0 (1 byte), Mdata starts at offset 3 (after S0/LEN/S1).
 */
static inline void
phy_hw_ccm_build_ble_job_lists(uint8_t *in_buf, uint8_t *out_buf,
                               uint16_t payload_len, uint8_t decrypt)
{
    uint16_t mdata_in_len;
    uint16_t mdata_out_len;

    if (decrypt) {
        mdata_in_len = payload_len + 4; /* ciphertext + MIC */
        mdata_out_len = payload_len;    /* plaintext only */
    } else {
        mdata_in_len = payload_len;      /* plaintext only */
        mdata_out_len = payload_len + 4; /* ciphertext + MIC */
    }

    g_ccm_alen = 1;
    /*
     * Per datasheet Fig. 45/46: input MLEN = l(m) for encrypt, l(c) for
     * decrypt.  MLEN tells the CCM how many bytes are in the MDATA field.
     */
    g_ccm_mlen = mdata_in_len;

    /*
     * Pre-mask the ADATA (header) byte with the BLE header mask (0xE3)
     * to zero out NESN/SN/MD bits before authentication.  This matches
     * what the peer does when encrypting.  The CCM ADATAMASK register
     * should do this automatically (reset value 0xE3), but we pre-mask
     * here to be safe — double-masking is idempotent.
     */
    g_ccm_adata_in = in_buf[0] & 0xE3;

    /* Input job list */
    g_ccm_in_jl[0].ptr = (uint8_t *)&g_ccm_alen;
    g_ccm_in_jl[0].attr_and_length = (CCM_ATTR_ALEN << 24) | 2;
    g_ccm_in_jl[1].ptr = (uint8_t *)&g_ccm_mlen;
    g_ccm_in_jl[1].attr_and_length = (CCM_ATTR_MLEN << 24) | 2;
    g_ccm_in_jl[2].ptr = &g_ccm_adata_in; /* pre-masked S0 byte */
    g_ccm_in_jl[2].attr_and_length = (CCM_ATTR_ADATA << 24) | 1;
    g_ccm_in_jl[3].ptr = in_buf + 3; /* payload after S0/LEN/S1 */
    g_ccm_in_jl[3].attr_and_length = (CCM_ATTR_MDATA << 24) | mdata_in_len;
    g_ccm_in_jl[4].ptr = NULL;
    g_ccm_in_jl[4].attr_and_length = 0;

    /* Output job list — must include ALEN + MLEN per datasheet Fig. 45/46 */
    g_ccm_out_jl[0].ptr = (uint8_t *)&g_ccm_out_alen;
    g_ccm_out_jl[0].attr_and_length = (CCM_ATTR_ALEN << 24) | 2;
    /*
     * MLEN output must NOT point at out_buf[1] (BLE LENGTH byte).
     * The CCM hardware writes the plaintext message length here, which
     * overwrites the BLE LENGTH field.  Redirect to a dummy so the
     * caller-set LENGTH is preserved.
     */
    g_ccm_out_jl[1].ptr = (uint8_t *)&g_ccm_out_mlen;
    g_ccm_out_jl[1].attr_and_length = (CCM_ATTR_MLEN << 24) | 2;
    /*
     * CCM ADATA output may be masked by ADATAMASK (0xE3), which zeroes
     * NESN/SN/MD bits.  Write it to a dummy so the pre-copied original
     * header in out_buf[0] is preserved (see phy_hw_ccm_post_rx_decrypt).
     */
    g_ccm_out_jl[2].ptr = &g_ccm_out_adata;
    g_ccm_out_jl[2].attr_and_length = (CCM_ATTR_ADATA << 24) | 1;
    g_ccm_out_jl[3].ptr = out_buf + 3; /* payload after header slot */
    g_ccm_out_jl[3].attr_and_length = (CCM_ATTR_MDATA << 24) | mdata_out_len;
    g_ccm_out_jl[4].ptr = NULL;
    g_ccm_out_jl[4].attr_and_length = 0;

    NRF_CCM->IN.PTR = (uint32_t)g_ccm_in_jl;
    NRF_CCM->OUT.PTR = (uint32_t)g_ccm_out_jl;
}

static inline void
phy_hw_ccm_init(void)
{
    /* CCM initialization is a no-op; hardware is configured per-packet */
}

static inline void
phy_hw_timer_start_trigger_set(uint32_t cputime)
{
    NRF_CPUTIME_TIMER->EVENTS_COMPARE[0] = 0;
    nrf_timer_cc_set(NRF_CPUTIME_TIMER, 0, cputime);
}

static inline int
phy_hw_timer_start_trigger_configure(uint32_t cputime)
{
    uint32_t cur_cc;
    uint32_t cntr;
    uint32_t delta;

    cur_cc = NRF_CPUTIME_TIMER->CC[0];
    cntr = os_cputime_get32();

    delta = cur_cc - cntr;
    if ((delta <= 3) && (delta != 0)) {
        return -1;
    }

    delta = cputime - cntr;
    if (((int32_t)delta < 0) || (delta < 3)) {
        return -1;
    }

    phy_hw_timer_start_trigger_set(cputime);

    return 0;
}

static inline void
phy_hw_timer_start_trigger_disable(void)
{
    NRF_CPUTIME_TIMER->EVENTS_COMPARE[0] = 0;
}

static inline void
phy_hw_ccm_setup_tx(uint8_t *in_ptr, uint8_t *out_ptr, uint8_t *scratch_ptr,
                    struct nrf_ccm_data *ccm_data)
{
    g_ccm_in_ptr = in_ptr;
    g_ccm_out_ptr = out_ptr;
    g_ccm_decrypt = 0;

    /*
     * Re-arm CCM explicitly for each TX packet. On nRF54L the RX path
     * toggles ENABLE around deferred decrypt setup, so relying on stale
     * peripheral state here can leave the next encrypted TX packet using an
     * undefined configuration window.
     */
    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
    NRF_CCM->EVENTS_ERROR = 0;
    NRF_CCM->EVENTS_END = 0;
    NRF_CCM->MODE = (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                    ble_phy_get_ccm_datarate();
    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
    phy_hw_ccm_set_key(ccm_data->key);
    phy_hw_ccm_set_nonce(ccm_data);
}

static inline void
phy_hw_ccm_setup_rx(uint8_t *in_ptr, uint8_t *out_ptr, uint8_t *scratch_ptr,
                    struct nrf_ccm_data *ccm_data)
{
    g_ccm_in_ptr = in_ptr;
    g_ccm_out_ptr = out_ptr;
    g_ccm_decrypt = 1;
    g_ccm_data_ptr = ccm_data;

    /*
     * Defer all CCM register writes (MODE, KEY, NONCE) to
     * post_rx_decrypt so they happen right before START.
     * The self-test (which passes) writes everything just before
     * START; the previous approach wrote KEY/NONCE here with a
     * hundreds-of-µs gap before START, and MIC always failed.
     */
}

static inline void
phy_hw_ccm_start(void)
{
    if (g_ccm_decrypt) {
        /* RX: don't start yet — triggered post-receive in ISR */
        return;
    }

    /* TX: build job lists now (payload is filled) and start encryption.
     * Set output header — CCM MLEN/ADATA outputs go to dummies, so the
     * RADIO-visible S0/LENGTH/S1 must be set explicitly here. */
    phy_hw_ccm_build_ble_job_lists(g_ccm_in_ptr, g_ccm_out_ptr, g_ccm_in_ptr[1], 0);
    g_ccm_out_ptr[0] = g_ccm_in_ptr[0];     /* S0 (header byte) */
    g_ccm_out_ptr[1] = g_ccm_in_ptr[1] + 4; /* LENGTH = plaintext + MIC */
    g_ccm_out_ptr[2] = 0;                   /* S1 */
    __DSB();
    nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);
}

/*
 * Post-receive CCM FastDecryption for nRF54L.
 * Called from rx_end_isr after full packet received.
 *
 * ALL CCM register setup (MODE, ENABLE, KEY, NONCE, job lists) is done
 * here, right before START.  Previous approach wrote MODE/KEY/NONCE in
 * setup_rx (hundreds of µs earlier) and MIC always failed, while the
 * boot self-test (which writes everything just before START) passes.
 * Deferring all writes eliminates any register-volatility or ENABLE-
 * clearing issues.
 *
 * BLE LENGTH field (enc_buf[1]) includes the 4-byte MIC for encrypted
 * packets, so plaintext_len = LENGTH - 4.
 */
static inline void
phy_hw_ccm_post_rx_decrypt(uint8_t *enc_buf, uint8_t *out_buf)
{
    uint16_t ble_len = enc_buf[1];
    uint16_t plaintext_len = (ble_len >= 4) ? (ble_len - 4) : 0;

    /* Copy S0/S1 from encrypted buffer; set LENGTH to plaintext size. */
    out_buf[0] = enc_buf[0];
    out_buf[1] = plaintext_len;
    out_buf[2] = enc_buf[2];

    /*
     * Full CCM setup — matches self-test sequence:
     *   ENABLE=0 → MODE → ENABLE=2 → events → KEY → NONCE →
     *   job lists → IN.PTR/OUT.PTR → DSB → START
     */
    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
    NRF_CCM->MODE = CCM_MODE_MODE_FastDecryption |
                    (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                    ble_phy_get_ccm_datarate();
    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
    NRF_CCM->EVENTS_END = 0;
    NRF_CCM->EVENTS_ERROR = 0;

    phy_hw_ccm_set_key(g_ccm_data_ptr->key);
    phy_hw_ccm_set_nonce(g_ccm_data_ptr);

    phy_hw_ccm_build_ble_job_lists(enc_buf, out_buf, plaintext_len, 1);

    __DSB();

    /* First-packet diagnostics — capture everything at START time */
    if (!g_phy_rx_enc_captured) {
        int _i;
        g_phy_rx_enc_mode = NRF_CCM->MODE;
        g_phy_rx_enc_enable = NRF_CCM->ENABLE;
        g_phy_rx_enc_radio_state = NRF_RADIO->STATE;
        for (_i = 0; _i < 8; _i++) {
            g_phy_rx_enc_in_at_start[_i] = enc_buf[_i];
        }
        /* Job list state at START time (before TX path overwrites) */
        g_phy_rx_enc_alen_at_start = g_ccm_alen;
        g_phy_rx_enc_mlen_at_start = g_ccm_mlen;
        g_phy_rx_enc_mdata_attr_at_start = g_ccm_in_jl[3].attr_and_length;
        g_phy_rx_enc_mdata_ptr_at_start = (uint32_t)g_ccm_in_jl[3].ptr;
        g_phy_rx_enc_adata_at_start = g_ccm_adata_in;
        /* ADATAMASK and SUBSCRIBE_START registers */
        g_phy_rx_enc_adatamask_at_start = *(volatile uint32_t *)0x50046548;
        g_phy_rx_enc_subscribe_start = NRF_CCM->SUBSCRIBE_START;
        g_phy_rx_enc_captured = 1;
    }
    nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);
}

static inline void
phy_hw_radio_fast_ru_setup(void)
{
    NRF_RADIO->TIMING =
        (RADIO_TIMING_RU_Fast << RADIO_TIMING_RU_Pos) & RADIO_TIMING_RU_Msk;
}

static inline void
phy_hw_radio_events_clear(void)
{
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->EVENTS_PHYEND = 0;
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
}

static inline void
phy_hw_radio_shorts_setup_tx(void)
{
    NRF_RADIO->SHORTS = RADIO_SHORTS_PHYEND_DISABLE_Msk | RADIO_SHORTS_READY_START_Msk;
}

static inline void
phy_hw_radio_shorts_setup_rx(void)
{
    /* nRF54L RADIO has no DISABLED_RSSISTOP shortcut */
    NRF_RADIO->SHORTS =
        RADIO_SHORTS_PHYEND_DISABLE_Msk | RADIO_SHORTS_READY_START_Msk |
        RADIO_SHORTS_ADDRESS_BCSTART_Msk | RADIO_SHORTS_ADDRESS_RSSISTART_Msk;
}

static inline void
phy_hw_radio_datawhite_set(uint8_t chan)
{
    NRF_RADIO->DATAWHITE = RADIO_DATAWHITE_ResetValue | chan;
}

static inline void
phy_hw_timer_configure(void)
{
    /* nRF54L TIMER10 runs at 32MHz; prescaler 5 → 32MHz/32 = 1MHz */
    NRF_TIMER0->PRESCALER = 5;
}

static inline void
phy_hw_radio_timer_task_stop(void)
{
    nrf_timer_task_trigger(NRF_TIMER0, NRF_TIMER_TASK_STOP);
}

/*
 * AAR scatter/gather job lists.
 * Input: [Hash][Prand][IRK0]...[IRKn][END] — max 19 entries (16 IRKs + 2 addr + 1 term)
 * Output: [resolved index buf][END] — 2 entries
 * Defined in nrf54l/phy.c.
 */
extern struct sg_job_entry g_aar_in_jl[19];
extern struct sg_job_entry g_aar_out_jl[2];

static inline void
phy_hw_aar_irk_setup(uint32_t *irk_ptr, uint32_t *scratch_ptr)
{
    int i;
    int num_irks = g_nrf_num_irks;
    struct sg_job_entry *entry;

    /* IRK entries in the input job list define how many IRKs AAR scans. */
    entry = &g_aar_in_jl[2];
    for (i = 0; i < num_irks; i++) {
        entry->ptr = (uint8_t *)&irk_ptr[i * 4];
        entry->attr_and_length = (AAR_ATTR_IRK << 24) | 16;
        entry++;
    }
    entry->ptr = NULL;
    entry->attr_and_length = 0;

    /* Output job list stores the first resolved IRK index as a 2-byte value. */
    g_nrf_aar_out_status = UINT16_MAX;
    g_aar_out_jl[0].ptr = (uint8_t *)&g_nrf_aar_out_status;
    g_aar_out_jl[0].attr_and_length = (11 << 24) | sizeof(g_nrf_aar_out_status);
    g_aar_out_jl[1].ptr = NULL;
    g_aar_out_jl[1].attr_and_length = 0;

    NRF_AAR->IN.PTR = (uint32_t)g_aar_in_jl;
    NRF_AAR->OUT.PTR = (uint32_t)g_aar_out_jl;
}

static inline void
phy_hw_aar_addrptr_set(uint8_t *dptr)
{
    /*
     * dptr points to start of device address (6 bytes):
     *   bytes [0..2] = hash (3 bytes, LSB first)
     *   bytes [3..5] = prand (3 bytes, LSB first)
     */
    g_aar_in_jl[0].ptr = dptr;
    g_aar_in_jl[0].attr_and_length = (AAR_ATTR_HASH << 24) | 3;
    g_aar_in_jl[1].ptr = dptr + 3;
    g_aar_in_jl[1].attr_and_length = (AAR_ATTR_PRAND << 24) | 3;
}

#endif /* H_PHY_HW_ */
