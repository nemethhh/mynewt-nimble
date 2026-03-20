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

#define AAR_ATTR_HASH   11
#define AAR_ATTR_PRAND  12
#define AAR_ATTR_IRK    13

/*
 * AAR output status — resolved IRK index written here by the output job list.
 * The nRF54L AAR EasyDMA writes exactly 2 bytes per resolved IRK; if the
 * job-list entry length exceeds 2 the write is silently dropped.
 */
extern uint16_t g_nrf_aar_out_status;
extern uint8_t g_nrf_num_irks;

#define NRF_TIMER0 NRF_TIMER10
#define NRF_DPPIC NRF_DPPIC10
#define NRF_RTC0 NRF_RTC10
#define NRF_AAR NRF_AAR00
#define NRF_CCM NRF_CCM00
#define NRF_ECB NRF_ECB00
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

#define RADIO_IRQn RADIO_0_IRQn
#define RADIO_INTENSET_ADDRESS_Msk RADIO_INTENSET00_ADDRESS_Msk
#define RADIO_INTENCLR_ADDRESS_Msk RADIO_INTENCLR00_ADDRESS_Msk
#define RADIO_INTENSET_DISABLED_Msk RADIO_INTENSET00_DISABLED_Msk
#define RADIO_INTENCLR_DISABLED_Msk RADIO_INTENCLR00_DISABLED_Msk

#define NRF_RADIO_INTENSET NRF_RADIO->INTENSET00

/* To disable all radio interrupts */
#define NRF_RADIO_IRQ_MASK_ALL  (RADIO_INTENSET00_READY_Msk    | \
                                 RADIO_INTENSET00_ADDRESS_Msk  | \
                                 RADIO_INTENSET00_PAYLOAD_Msk  | \
                                 RADIO_INTENSET00_PHYEND_Msk   | \
                                 RADIO_INTENSET00_DISABLED_Msk | \
                                 RADIO_INTENSET00_DEVMATCH_Msk | \
                                 RADIO_INTENSET00_DEVMISS_Msk  | \
                                 RADIO_INTENSET00_BCMATCH_Msk  | \
                                 RADIO_INTENSET00_CRCOK_Msk    | \
                                 RADIO_INTENSET00_CRCERROR_Msk)

#define NRF_AAR_NIRK NRF_AAR->MAXRESOLVED

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

#define CCM_MODE_DATARATE_125Kbps CCM_MODE_DATARATE_125Kbit
#define CCM_MODE_DATARATE_500Kbps CCM_MODE_DATARATE_500Kbit

#define NRF_CCM_STATUS NRF_CCM->MACSTATUS
#define NRF_CCM_EVENTS_END NRF_CCM->EVENTS_END

#define CCM_ATTR_ALEN   11
#define CCM_ATTR_MLEN   12
#define CCM_ATTR_ADATA  13
#define CCM_ATTR_MDATA  14

uint32_t ble_phy_get_ccm_datarate(void);

/*
 * CCM scatter/gather job lists and state.
 * Input: [Alen][Mlen][Adata][Mdata][END] — 5 entries
 * Output: [Adata][Mdata][END] — 3 entries
 * Defined in nrf54l/phy.c.
 */
extern struct sg_job_entry g_ccm_in_jl[5];
extern struct sg_job_entry g_ccm_out_jl[3];
extern uint16_t g_ccm_alen;
extern uint16_t g_ccm_mlen;
extern uint8_t *g_ccm_in_ptr;
extern uint8_t *g_ccm_out_ptr;
extern uint8_t g_ccm_decrypt;

/*
 * nRF54L KEY.VALUE byte order is reversed vs nRF52/nRF53.
 * KEY.VALUE[0] gets the last 4 bytes of the key (word-reversed + byte-swapped).
 */
static inline void
phy_hw_ccm_set_key(const uint8_t *key)
{
    const uint32_t *kp = (const uint32_t *)key;
    NRF_CCM->KEY.VALUE[0] = __builtin_bswap32(kp[3]);
    NRF_CCM->KEY.VALUE[1] = __builtin_bswap32(kp[2]);
    NRF_CCM->KEY.VALUE[2] = __builtin_bswap32(kp[1]);
    NRF_CCM->KEY.VALUE[3] = __builtin_bswap32(kp[0]);
}

/*
 * Build 13-byte BLE CCM nonce from nrf_ccm_data fields,
 * then write reversed to NONCE.VALUE[0..3].
 */
static inline void
phy_hw_ccm_set_nonce(struct nrf_ccm_data *ccm_data)
{
    uint8_t nonce[16];
    const uint32_t *np;

    memcpy(&nonce[0], &ccm_data->pkt_counter, 5);
    nonce[5] = ccm_data->dir_bit;
    memcpy(&nonce[6], ccm_data->iv, 7);
    nonce[13] = 0;
    nonce[14] = 0;
    nonce[15] = 0;

    np = (const uint32_t *)nonce;
    NRF_CCM->NONCE.VALUE[0] = __builtin_bswap32(np[3]);
    NRF_CCM->NONCE.VALUE[1] = __builtin_bswap32(np[2]);
    NRF_CCM->NONCE.VALUE[2] = __builtin_bswap32(np[1]);
    NRF_CCM->NONCE.VALUE[3] = __builtin_bswap32(np[0]);
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
        mdata_in_len = payload_len + 4;  /* ciphertext + MIC */
        mdata_out_len = payload_len;     /* plaintext only */
    } else {
        mdata_in_len = payload_len;      /* plaintext only */
        mdata_out_len = payload_len + 4; /* ciphertext + MIC */
    }

    g_ccm_alen = 1;
    g_ccm_mlen = payload_len;

    /* Input job list */
    g_ccm_in_jl[0].ptr = (uint8_t *)&g_ccm_alen;
    g_ccm_in_jl[0].attr_and_length = (CCM_ATTR_ALEN << 24) | 2;
    g_ccm_in_jl[1].ptr = (uint8_t *)&g_ccm_mlen;
    g_ccm_in_jl[1].attr_and_length = (CCM_ATTR_MLEN << 24) | 2;
    g_ccm_in_jl[2].ptr = in_buf;       /* S0 byte */
    g_ccm_in_jl[2].attr_and_length = (CCM_ATTR_ADATA << 24) | 1;
    g_ccm_in_jl[3].ptr = in_buf + 3;   /* payload after S0/LEN/S1 */
    g_ccm_in_jl[3].attr_and_length = (CCM_ATTR_MDATA << 24) | mdata_in_len;
    g_ccm_in_jl[4].ptr = NULL;
    g_ccm_in_jl[4].attr_and_length = 0;

    /* Output job list */
    g_ccm_out_jl[0].ptr = out_buf;     /* S0 passthrough */
    g_ccm_out_jl[0].attr_and_length = (CCM_ATTR_ADATA << 24) | 1;
    g_ccm_out_jl[1].ptr = out_buf + 3; /* payload after header slot */
    g_ccm_out_jl[1].attr_and_length = (CCM_ATTR_MDATA << 24) | mdata_out_len;
    g_ccm_out_jl[2].ptr = NULL;
    g_ccm_out_jl[2].attr_and_length = 0;

    NRF_CCM->IN.PTR = (uint32_t)g_ccm_in_jl;
    NRF_CCM->OUT.PTR = (uint32_t)g_ccm_out_jl;
}

static inline void
phy_hw_ccm_init(void)
{
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
phy_hw_ccm_setup_tx(uint8_t *in_ptr, uint8_t *out_ptr,
                    uint8_t *scratch_ptr, struct nrf_ccm_data *ccm_data)
{
    g_ccm_in_ptr = in_ptr;
    g_ccm_out_ptr = out_ptr;
    g_ccm_decrypt = 0;

    NRF_CCM->EVENTS_ERROR = 0;
    NRF_CCM->EVENTS_END = 0;
    NRF_CCM->MODE = (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                    ble_phy_get_ccm_datarate();
    phy_hw_ccm_set_key(ccm_data->key);
    phy_hw_ccm_set_nonce(ccm_data);
}

static inline void
phy_hw_ccm_setup_rx(uint8_t *in_ptr, uint8_t *out_ptr,
                    uint8_t *scratch_ptr, struct nrf_ccm_data *ccm_data)
{
    g_ccm_in_ptr = in_ptr;
    g_ccm_out_ptr = out_ptr;
    g_ccm_decrypt = 1;

    NRF_CCM->EVENTS_ERROR = 0;
    NRF_CCM->EVENTS_END = 0;
    NRF_CCM->MODE = CCM_MODE_MODE_FastDecryption |
                    (CCM_MODE_MACLEN_M4 << CCM_MODE_MACLEN_Pos) |
                    ble_phy_get_ccm_datarate();
    phy_hw_ccm_set_key(ccm_data->key);
    phy_hw_ccm_set_nonce(ccm_data);
}

static inline void
phy_hw_ccm_start(void)
{
    if (g_ccm_decrypt) {
        /* RX: don't start yet — triggered post-receive in ISR */
        return;
    }

    /* TX: build job lists now (payload is filled) and start encryption */
    phy_hw_ccm_build_ble_job_lists(g_ccm_in_ptr, g_ccm_out_ptr,
                                   g_ccm_in_ptr[1], 0);
    nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);
}

/*
 * Post-receive CCM FastDecryption for nRF54L.
 * Called from rx_end_isr after full packet received.
 * Builds job lists, copies header fields, triggers decrypt.
 */
static inline void
phy_hw_ccm_post_rx_decrypt(uint8_t *enc_buf, uint8_t *out_buf)
{
    uint16_t mlen = enc_buf[1];

    /* Copy S0/LEN/S1 from encrypted buffer to output */
    out_buf[0] = enc_buf[0];
    out_buf[1] = enc_buf[1];
    out_buf[2] = enc_buf[2];

    phy_hw_ccm_build_ble_job_lists(enc_buf, out_buf, mlen, 1);

    NRF_CCM->EVENTS_END = 0;
    nrf_ccm_task_trigger(NRF_CCM, NRF_CCM_TASK_START);
}

static inline void
phy_hw_radio_fast_ru_setup(void)
{
    NRF_RADIO->TIMING = (RADIO_TIMING_RU_Fast << RADIO_TIMING_RU_Pos) &
                        RADIO_TIMING_RU_Msk;
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
    NRF_RADIO->SHORTS = RADIO_SHORTS_PHYEND_DISABLE_Msk |
                        RADIO_SHORTS_READY_START_Msk;
}

static inline void
phy_hw_radio_shorts_setup_rx(void)
{
    /* nRF54L RADIO has no DISABLED_RSSISTOP shortcut */
    NRF_RADIO->SHORTS = RADIO_SHORTS_PHYEND_DISABLE_Msk |
                        RADIO_SHORTS_READY_START_Msk |
                        RADIO_SHORTS_ADDRESS_BCSTART_Msk |
                        RADIO_SHORTS_ADDRESS_RSSISTART_Msk;
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

    /* IRK entries start at index 2 (0=Hash, 1=Prand set in addrptr_set) */
    entry = &g_aar_in_jl[2];
    for (i = 0; i < num_irks; i++) {
        entry->ptr = (uint8_t *)&irk_ptr[i * 4];
        entry->attr_and_length = (AAR_ATTR_IRK << 24) | 16;
        entry++;
    }
    /* Terminate input job list */
    entry->ptr = NULL;
    entry->attr_and_length = 0;

    /* Output: resolved IRK index/status word + terminator */
    g_nrf_aar_out_status = UINT16_MAX;
    g_aar_out_jl[0].ptr = (uint8_t *)&g_nrf_aar_out_status;
    g_aar_out_jl[0].attr_and_length = (11 << 24) | sizeof(g_nrf_aar_out_status);
    g_aar_out_jl[1].ptr = NULL;
    g_aar_out_jl[1].attr_and_length = 0;

    NRF_AAR->MAXRESOLVED = num_irks;
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
