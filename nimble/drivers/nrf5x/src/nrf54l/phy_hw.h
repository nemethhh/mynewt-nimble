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
#define AAR_ATTR_OUTPUT 11

/*
 * AAR output status — resolved IRK index written here by the output job list.
 * The nRF54L AAR EasyDMA writes exactly 2 bytes per resolved IRK; if the
 * job-list entry length exceeds 2 the write is silently dropped.
 */
extern uint16_t g_nrf_aar_out_status;
extern uint8_t g_nrf_num_irks;

#define NRF_TIMER0 NRF_TIMER10
#define NRF_DPPIC  NRF_DPPIC10
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

static inline void
phy_hw_ccm_init(void)
{
    /* CCM initialization is a no-op; hardware is configured per-packet */
}

/* CCM functions — implemented in nrf54l/phy.c */
void phy_hw_ccm_setup_tx(uint8_t *in_ptr, uint8_t *out_ptr,
                         uint8_t *scratch_ptr, struct nrf_ccm_data *ccm_data);
void phy_hw_ccm_setup_rx(uint8_t *in_ptr, uint8_t *out_ptr,
                         uint8_t *scratch_ptr, struct nrf_ccm_data *ccm_data);
void phy_hw_ccm_start(void);
void phy_hw_ccm_tx_wait_complete(void);
void phy_hw_ccm_post_rx_decrypt(uint8_t *enc_buf, uint8_t *out_buf);

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
    g_aar_out_jl[0].attr_and_length =
        (AAR_ATTR_OUTPUT << 24) | sizeof(g_nrf_aar_out_status);
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
