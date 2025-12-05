/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body (RX — verify signed DHT data and show on 7-segment)
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "tim.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <string.h>
//#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/memory_buffer_alloc.h"

#include "stm32f0xx_ll_rcc.h"
#include "stm32f0xx_ll_system.h"
#include "stm32f0xx_ll_bus.h"
#include "stm32f0xx_ll_gpio.h"
#include "stm32f0xx_ll_exti.h"
#include "stm32f0xx_ll_utils.h"
#include "stm32f0xx_ll_cortex.h"
#include "stm32f0xx_ll_tim.h"

#include "DHT.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
#pragma pack(push,1)
typedef struct {
  uint16_t sof;      // 0xAA55
  uint8_t  ver;      // 1
  uint32_t seq;
  uint32_t ts_ms;
  int16_t  temp_c;   // целое, градусы C
  uint16_t hum_pc;   // целое, %
  uint8_t  hmac[8];  // первые 8 байт HMAC-SHA256
  uint16_t eof;      // 0x55AA
} hmac_frame_t;
#pragma pack(pop)

static int start_count = 0;
static int tim2_counter = 0;

static int sysytick_counter_top  = 4;
static int delay_counter_top = 1;
static int ms = 0; //0.....1000
static int ms_old = 0;

static int sysytick_counter = 0;
static int delay_counter = 0;

static int  indicator_number = 0000;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define SOF_WORD   0xAA55u
#define EOF_WORD   0x55AAu

// Публичный ключ для проверки подписи (65 байт: 0x04 || X || Y)
static const uint8_t hmac_key[32] = {
  0xfd, 0xc5, 0xbe, 0xb0, 0x72, 0x1c, 0x64, 0x04,
  0x4f, 0x3a, 0x05, 0xc3, 0x6f, 0xdc, 0xab, 0xb8,
  0xb5, 0x97, 0xbd, 0xd1, 0xc7, 0x54, 0xa1, 0x35,
  0xf7, 0x05, 0x65, 0xde, 0xce, 0xb2, 0x86, 0x34
};

/* Лёгкий симметричный ключ для PRESENT-80 (10 байт = 80 бит) */
static const uint8_t present80_key[10] = {
    0x01, 0x23, 0x45, 0x67, 0x89,
    0xAB, 0xCD, 0xEF, 0x11, 0x22
};
/* Можно поменять на свои случайные байты, но одинаковые на TX и RX */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
static uint8_t mbedtls_heap[6*1024];

/**
  * Управление разрядами индикатора (2 разряда на PB10 и PB11).
  * Активный уровень — низкий (как в старом проекте: Reset = ON).
  */
static inline void digits_off(void)
{
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_10 | GPIO_PIN_11, GPIO_PIN_SET);  // OFF
}


static inline void digit_on(uint16_t pin)
{
    HAL_GPIO_WritePin(GPIOB, pin, GPIO_PIN_RESET);                      // ON
}

/**
  * Значение для отображения (0..99) разбивается на левый и правый разряд.
  */
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
static uint8_t  show_temp = 1;   // 1 — показываем температуру, 0 — влажность
static int16_t  last_t = 0;
static uint16_t last_h = 0;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */
/* === PRESENT-80: лёгкий блочный шифр для шифрования измерений === */

/* 4-битный S-box PRESENT (взято из описания алгоритма) */
static const uint8_t present_sbox[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

/* P-слой PRESENT: позиция битов после перестановки */
static const uint8_t present_pbox[64] = {
    /* i:  0..15  */
    0, 16, 32, 48,  1, 17, 33, 49,
    2, 18, 34, 50,  3, 19, 35, 51,
    /* i: 16..31  */
    4, 20, 36, 52,  5, 21, 37, 53,
    6, 22, 38, 54,  7, 23, 39, 55,
    /* i: 32..47  */
    8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    /* i: 48..63  */
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};

/* Вспомогательная: запись 32-битного числа в big-endian */
static void put_be32(uint32_t v, uint8_t *out)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

/* Обновление 80-битного ключа: циклический сдвиг, S-box, XOR номера раунда */
static void present80_update_key(uint8_t key[10], uint8_t round)
{
    uint8_t old[10];
    uint8_t newk[10] = {0};

    memcpy(old, key, 10);

    /* 1) циклический сдвиг на 61 бит влево по всей 80-битной регистровой цепочке */
    for (int i = 0; i < 80; ++i) {
        int src = (i + 61) % 80;    // откуда брать бит
        int src_byte = src / 8;
        int src_bit  = src % 8;
        uint8_t bit = (old[src_byte] >> src_bit) & 0x01;

        int dst_byte = i / 8;
        int dst_bit  = i % 8;
        if (bit) {
            newk[dst_byte] |= (uint8_t)(1u << dst_bit);
        }
    }

    memcpy(key, newk, 10);

    /* 2) прогоняем старший полубайт через тот же S-box */
    uint8_t high = (uint8_t)(key[9] >> 4);          // старшие 4 бита последнего байта
    high = present_sbox[high];
    key[9] = (uint8_t)((high << 4) | (key[9] & 0x0F));

    /* 3) XOR номера раунда в несколько бит ключа (для простоты — младшие 5 бит key[1]) */
    key[1] ^= (uint8_t)(round & 0x1F);
}

/* Один раунд pLayer: перестановка битов в состоянии */
static void present_pLayer(uint8_t state[8])
{
    uint8_t tmp[8] = {0};

    for (int i = 0; i < 64; ++i) {
        uint8_t bit = (state[i / 8] >> (i % 8)) & 0x01;
        if (bit) {
            uint8_t pos = present_pbox[i];
            tmp[pos / 8] |= (uint8_t)(1u << (pos % 8));
        }
    }

    memcpy(state, tmp, 8);
}

/* Шифрование одного 64-битного блока с помощью PRESENT-80 */
static void present80_encrypt_block(const uint8_t master_key[10],
                                    const uint8_t in[8],
                                    uint8_t out[8])
{
    uint8_t state[8];
    uint8_t key[10];

    memcpy(state, in, 8);
    memcpy(key, master_key, 10);

    /* 31 раунд */
    for (uint8_t round = 1; round <= 31; ++round) {
        /* 1. AddRoundKey: XOR состояния с первыми 8 байтами ключа */
        for (int i = 0; i < 8; ++i) {
            state[i] ^= key[i];
        }

        /* 2. SubCells: применяем S-box к каждому 4-битному полубайту */
        for (int i = 0; i < 8; ++i) {
            uint8_t hi = (uint8_t)(state[i] >> 4);
            uint8_t lo = (uint8_t)(state[i] & 0x0F);
            hi = present_sbox[hi];
            lo = present_sbox[lo];
            state[i] = (uint8_t)((hi << 4) | lo);
        }

        /* 3. PermuteBits: P-слой */
        present_pLayer(state);

        /* 4. Обновляем ключ к следующему раунду */
        present80_update_key(key, round);
    }

    /* Финальный XOR с ключом (post-whitening) */
    for (int i = 0; i < 8; ++i) {
        state[i] ^= key[i];
    }

    memcpy(out, state, 8);
}

/* === Шифрование/расшифрование измерений в кадре (CTR на PRESENT) === */

static void present_crypt_measurements(hmac_frame_t *packet)
{
    uint8_t ctr[8];
    uint8_t keystream[8];

    /* Счётчик = seq || ts_ms (по 32 бита, big-endian) */
    put_be32(packet->seq,   &ctr[0]);
    put_be32(packet->ts_ms, &ctr[4]);

    /* keystream = PRESENT_K(ctr) */
    present80_encrypt_block(present80_key, ctr, keystream);



    /* Шифруем/расшифровываем 4 байта: temp_c (2 байта) + hum_pc (2 байта) */
    uint8_t *m = (uint8_t*)&packet->temp_c;
    for (int i = 0; i < 4; ++i) {
        m[i] ^= keystream[i];
    }
    /* Повторный вызов этой функции на RX выполняет обратную операцию (XOR) */
}
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
static void rcc_config()
{
    /* Set FLASH latency */
    LL_FLASH_SetLatency(LL_FLASH_LATENCY_1);

    /* Enable HSI and wait for activation*/
    LL_RCC_HSI_Enable();
    while (LL_RCC_HSI_IsReady() != 1);

    /* Main PLL configuration and activation */
    LL_RCC_PLL_ConfigDomain_SYS(LL_RCC_PLLSOURCE_HSI_DIV_2,
                                LL_RCC_PLL_MUL_12);

    LL_RCC_PLL_Enable();
    while (LL_RCC_PLL_IsReady() != 1);

    /* Sysclk activation on the main PLL */
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);
    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_PLL);
    while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_PLL);

    /* Set APB1 prescaler */
    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

    /* Update CMSIS variable (which can be updated also
     * through SystemCoreClockUpdate function) */
    SystemCoreClock = 48000000;
}

/*
 * Clock on GPIOC and set two led pins
 */
static void gpio_config(void)
{
    /*
     * Init two default LEDs
     */
    LL_AHB1_GRP1_EnableClock(LL_AHB1_GRP1_PERIPH_GPIOC);
    LL_GPIO_SetPinMode(GPIOC, LL_GPIO_PIN_8, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOC, LL_GPIO_PIN_9, LL_GPIO_MODE_OUTPUT);
    //LL_GPIO_SetPinMode(GPIOC, LL_GPIO_PIN_0, LL_GPIO_MODE_OUTPUT);

    /*
     * Init port for indicator
     */
    LL_AHB1_GRP1_EnableClock(LL_AHB1_GRP1_PERIPH_GPIOB);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_0, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_1, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_2, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_3, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_4, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_5, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_6, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_7, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_8, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_9, LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_10, LL_GPIO_MODE_OUTPUT);
    /*
     * Init port for USER button
     */
    LL_AHB1_GRP1_EnableClock(LL_AHB1_GRP1_PERIPH_GPIOA);
    LL_GPIO_SetPinPull(GPIOA, LL_GPIO_PIN_0, LL_GPIO_PULL_DOWN);

    /*
     * Init port for DHT11
     */
    LL_AHB1_GRP1_EnableClock(LL_AHB1_GRP1_PERIPH_GPIOD);
    LL_GPIO_SetPinMode(GPIOD, LL_GPIO_PIN_2, LL_GPIO_MODE_INPUT);
    LL_GPIO_SetPinPull(GPIOD, LL_GPIO_PIN_2, LL_GPIO_PULL_UP);
    //LL_GPIO_SetPinSpeed(GPIOD, LL_GPIO_PIN_2, LL_GPIO_SPEED_FREQ_HIGH);
    return;
}

__attribute__((naked)) static void delay(void)
{
    asm ("push {r7, lr}");    // Сохраняем регистр-ссылку LR и R7 в стек (чтобы вернуться обратно)
    asm ("ldr r6, [pc, #8]"); // Загружаем число 0x5b8d80 в регистр R6
    asm ("sub r6, #1");       // вычитаем 1
    asm ("cmp r6, #0");       // Проверяем на 0
    asm ("bne delay+0x4");    // Если не 0, то возвращаемся на строчку 3
    asm ("pop {r7, pc}");     // Выгружаем LR и R7 в регистры PC и R7,
                              // тем самым возвращаясь в место вызова функции
    asm (".word 0x5b8d80");   //6000000
//#endif
}

__attribute__((naked)) static void delay_10ms(void)
{
    asm ("push {r7, lr}");
    asm ("ldr r6, [pc, #8]");
    asm ("sub r6, #1");
    asm ("cmp r6, #0");
    asm ("bne delay_10ms+0x4");
    asm ("pop {r7, pc}");
    asm (".word 0xea60"); //60000
}

/*
 * Configure timer to counter mode
 */
static void timers_config(void)  //1s
{
    /*
     * Setup timer
     */
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_TIM2);
    LL_TIM_SetPrescaler(TIM2, 47999);
    LL_TIM_SetAutoReload(TIM2, 1);		//-->1ms
    LL_TIM_SetCounterMode(TIM2, LL_TIM_COUNTERMODE_UP);
    LL_TIM_EnableIT_UPDATE(TIM2);
    LL_TIM_EnableCounter(TIM2);
    /*
     * Setup NVIC
     */
    NVIC_EnableIRQ(TIM2_IRQn);
    NVIC_SetPriority(TIM2_IRQn, 0);
    return;
}

void TIM2_IRQHandler(void)
{
    if(start_count)
    {
    	tim2_counter++;
    }

    sysytick_counter = (sysytick_counter + 1) % sysytick_counter_top; //1кГц --> 1Гц,  1ms -->1s
    delay_counter = (delay_counter + 1) % delay_counter_top;
    ms = ms + 1;

    set_all_indicators(indicator_number);

    LL_TIM_ClearFlag_UPDATE(TIM2);
}

void my_delay(int time_ms)
{
	start_count = 1;
	while(tim2_counter <= time_ms);
	start_count = 0;
	tim2_counter = 0;
	return;
}

//==============================================================================

static void exti_config(void)
{
    LL_APB1_GRP2_EnableClock(LL_APB1_GRP2_PERIPH_SYSCFG);

    LL_SYSCFG_SetEXTISource(LL_SYSCFG_EXTI_PORTA, LL_SYSCFG_EXTI_LINE0);
    LL_EXTI_EnableIT_0_31(LL_EXTI_LINE_0);

    LL_EXTI_EnableRisingTrig_0_31(LL_EXTI_LINE_0);

    NVIC_EnableIRQ(EXTI0_1_IRQn);
    NVIC_SetPriority(EXTI0_1_IRQn, 0);
}


void EXTI0_1_IRQHandler(void)
{
	if((ms - ms_old) > 50)
     {
    	 show_temp = (show_temp + 1)%2;
         int val = (show_temp
             ? (int)(last_t < 0 ? 0 : (last_t > 99 ? 99 : last_t))
             : (int)(last_h > 99 ? 99 : last_h));

         indicator_number = val;
    	 set_all_indicators(indicator_number);

     }

    ms_old = ms;
//    HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
//    HAL_Delay(1000);
    LL_EXTI_ClearFlag_0_31(LL_EXTI_LINE_0);
}


//===============================================================================

static void systick_config(void)
{
    LL_InitTick(48000000, 1000); //--> 1кГц
    LL_SYSTICK_EnableIT();
    NVIC_SetPriority(SysTick_IRQn, 0);
    return;
}



//===================================================================================

static void set_indicator(uint8_t number)
{
    /*
     * Put all pins for indicator together (for segments only)
     */
    static uint32_t mask = LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | \
                           LL_GPIO_PIN_3 | LL_GPIO_PIN_4 | LL_GPIO_PIN_5 | \
                           LL_GPIO_PIN_6 ;
    /*
     * Таблица символов для 7-сегментного индикатора:
     * 0-9: цифры
     * 10-16: специальные символы (t, P, h, u, -, пусто)
     */
    static const uint32_t decoder[] = {
        /* Цифры 0-9 (проверяем правильность) */
        /* 0: abcdef */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | \
        LL_GPIO_PIN_4 | LL_GPIO_PIN_5,                                     // 0

        /* 1: bc */
        LL_GPIO_PIN_1 | LL_GPIO_PIN_2,                                     // 1

        /* 2: abdeg */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_3 | LL_GPIO_PIN_4 | \
        LL_GPIO_PIN_6,                                                     // 2

        /* 3: abcdg */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | \
        LL_GPIO_PIN_6,                                                     // 3

        /* 4: bcfg */
        LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_5 | LL_GPIO_PIN_6,     // 4

        /* 5: acdfg */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | LL_GPIO_PIN_5 | \
        LL_GPIO_PIN_6,                                                     // 5

        /* 6: acdefg */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | LL_GPIO_PIN_4 | \
        LL_GPIO_PIN_5 | LL_GPIO_PIN_6,                                     // 6

        /* 7: abc */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2,                     // 7

        /* 8: abcdefg */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | \
        LL_GPIO_PIN_4 | LL_GPIO_PIN_5 | LL_GPIO_PIN_6,                     // 8

        /* 9: abcdfg */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | \
        LL_GPIO_PIN_5 | LL_GPIO_PIN_6,                                     // 9

        /* Специальные символы */
        /* 10: 't' - adefg (верхняя горизонталь + средняя + нижняя левая) */
        LL_GPIO_PIN_3 | LL_GPIO_PIN_4 | LL_GPIO_PIN_5 | \
        LL_GPIO_PIN_6,                                                     // 10: 't'

        /* 11: 'P' - abefg (почти как 8 без c и d) */
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_4 | LL_GPIO_PIN_5 | \
        LL_GPIO_PIN_6,                                                     // 11: 'P'

        /* 12: 'h' - cefg (как 4, но без b) */
        LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_4 | LL_GPIO_PIN_5 | \
        LL_GPIO_PIN_6,                                                     // 12: 'h'

        /* 13: 'u' - cde (нижняя часть буквы u) */
        LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | LL_GPIO_PIN_4 | \
        LL_GPIO_PIN_5                                                      // 13: 'u'
    };
    const uint8_t max_num = sizeof(decoder) / sizeof(uint32_t);
    uint32_t port_state = 0;

    /*
     * Read current state and do not change pins that are not related to
     * indicator (that is done by using masking)
     */
    port_state = LL_GPIO_ReadOutputPort(GPIOB);

    /*
     * Преобразуем входной символ (0-15) в битовую маску сегментов
     */
    port_state = (port_state & ~mask) | decoder[number % max_num];
    LL_GPIO_WriteOutputPort(GPIOB, port_state);
    return;
}

void set_all_indicators(indicator_number)
{
	switch(sysytick_counter)
	{
		case 0:
		LL_GPIO_ResetOutputPin(GPIOB, LL_GPIO_PIN_7);
		LL_GPIO_SetOutputPin(GPIOB, LL_GPIO_PIN_8|LL_GPIO_PIN_9|LL_GPIO_PIN_10);
		set_indicator(indicator_number%10);
		break;

		case 1:
		LL_GPIO_ResetOutputPin(GPIOB, LL_GPIO_PIN_8);
		LL_GPIO_SetOutputPin(GPIOB, LL_GPIO_PIN_7|LL_GPIO_PIN_9|LL_GPIO_PIN_10);
		set_indicator((indicator_number%100)/10);
		break;

		case 2:
	    	LL_GPIO_ResetOutputPin(GPIOB, LL_GPIO_PIN_9);
	    	LL_GPIO_SetOutputPin(GPIOB, LL_GPIO_PIN_7|LL_GPIO_PIN_8|LL_GPIO_PIN_10);
	    	set_indicator((indicator_number%1000)/100);
	    	break;

	    	case 3:
	  	LL_GPIO_ResetOutputPin(GPIOB, LL_GPIO_PIN_10);
	   	LL_GPIO_SetOutputPin(GPIOB, LL_GPIO_PIN_7|LL_GPIO_PIN_8|LL_GPIO_PIN_9);
	   	set_indicator((indicator_number%10000)/1000);
	   	break;
	}
}

/**
 * Вычисляет HMAC-SHA256 подпись для данных
 */
/**
 * Упрощенная HMAC-SHA256 реализация без mbedtls_md
 */
static int compute_hmac_sha256(const uint8_t *data, size_t data_len, uint8_t *hmac)
{
    mbedtls_sha256_context ctx;
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tmp_hash[32];
    size_t i;

    // Инициализация pads
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);

    // Копируем ключ (предполагаем, что ключ 32 байта или меньше)
    if (sizeof(hmac_key) <= 64) {
        memcpy(k_ipad, hmac_key, sizeof(hmac_key));
        memcpy(k_opad, hmac_key, sizeof(hmac_key));
    } else {
        // Если ключ длиннее - хешируем его
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, hmac_key, sizeof(hmac_key));
        mbedtls_sha256_finish(&ctx, k_ipad);
        mbedtls_sha256_free(&ctx);
        memcpy(k_opad, k_ipad, 32);
    }

    // XOR с константами
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }

    // Внутренний хеш: hash((key ^ ipad) || message)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, k_ipad, 64);
    mbedtls_sha256_update(&ctx, data, data_len);
    mbedtls_sha256_finish(&ctx, tmp_hash);
    mbedtls_sha256_free(&ctx);

    // Внешний хеш: hash((key ^ opad) || inner_hash)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, k_opad, 64);
    mbedtls_sha256_update(&ctx, tmp_hash, 32);
    mbedtls_sha256_finish(&ctx, hmac);
    mbedtls_sha256_free(&ctx);

    return 0;
}
static int verify_hmac_packet(const hmac_frame_t *packet)
{
    uint8_t computed_hmac[32];
    uint8_t received_hmac[8];

    memcpy(received_hmac, packet->hmac, 8);

    uint8_t *data_to_verify = (uint8_t*)&packet->ver;
    size_t data_len = sizeof(hmac_frame_t) - sizeof(uint16_t) - sizeof(uint8_t[8]) - sizeof(uint16_t);

    if (compute_hmac_sha256(data_to_verify, data_len, computed_hmac) != 0) {
        return -1;
    }

    return memcmp(computed_hmac, received_hmac, 8) == 0 ? 0 : -1;
}

static HAL_StatusTypeDef uart_recv_exact(uint8_t *buf, uint16_t len, uint32_t timeout_ms)
{
  uint32_t start = HAL_GetTick();
  uint16_t got   = 0;

  while (got < len) {
    uint32_t elapsed = HAL_GetTick() - start;
    if (elapsed >= timeout_ms) {
      return HAL_TIMEOUT;
    }
    uint32_t remain = timeout_ms - elapsed;
    if (HAL_UART_Receive(&huart2, buf + got, 1, (remain ? remain : 1)) != HAL_OK) {
      continue;
    }
    got++;
  }
  return HAL_OK;
}
#include <string.h>   // обязательно, для strlen, strstr, memset

// UART, к которому подключён ESP-01 на RX-плате
#define ESP_UART huart2

// Сбросить приёмный буфер UART (выбросить мусор)
static void esp_clear_rx(void)
{
    uint8_t c;
    while (HAL_UART_Receive(&ESP_UART, &c, 1, 10) == HAL_OK) {
        // просто читаем до таймаута
    }
}

// Отправить строку (обязательно с "\r\n" в конце!)
static HAL_StatusTypeDef esp_send_line(const char *s)
{
    return HAL_UART_Transmit(&ESP_UART, (uint8_t*)s, strlen(s), 1000);
}

// Ждём, пока в ответе появится подстрока keyword (как их echoFind)
static int esp_wait_keyword(const char *keyword, uint32_t timeout_ms)
{
    uint8_t c;
    char buf[256];
    size_t pos = 0;
    size_t key_len = strlen(keyword);
    uint32_t start = HAL_GetTick();

    memset(buf, 0, sizeof(buf));

    while ((HAL_GetTick() - start) < timeout_ms && pos < sizeof(buf) - 1)
    {
        if (HAL_UART_Receive(&ESP_UART, &c, 1, 50) == HAL_OK)
        {
            buf[pos++] = (char)c;
            buf[pos]   = '\0';

            if (pos >= key_len) {
                if (strstr(buf, keyword) != NULL) {
                    return 0;   // нашли keyword
                }
            }
        }
    }
    return -1; // не нашли за timeout
}

// Аналог SendCommand(cmd, ack): отправить команду и дождаться ack
// Если ack == NULL или "", просто отправляем и не ждём.
static int esp_send_cmd(const char *cmd, const char *ack, uint32_t timeout_ms)
{
    esp_clear_rx();

    if (esp_send_line(cmd) != HAL_OK)
        return -10; // ошибка отправки по UART

    if (ack == NULL || ack[0] == '\0')
        return 0;   // ничего ждать не нужно

    if (esp_wait_keyword(ack, timeout_ms) == 0)
        return 0;   // всё ок

    return -11;     // не дождались ack
}

// Инициализация ESP-01 на RX-плате.
// Делает из него точку доступа STM_RX + TCP-сервер на порту 5000.
//
// Возвращает 0  — всё ОК
// Неноль        — ошибка (по коду можно понять, на каком шаге упало)
int wifi_init_rx(void)
{
    int r;

    // Даём ESP стабилизироваться после подачи питания
    HAL_Delay(2000);
    esp_clear_rx();

    // ШАГ 1. Проверяем связь: "AT"
    r = esp_send_cmd("AT\r\n", "OK", 3000);
    if (r != 0) {
        while(1) {
        	HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
			HAL_Delay(1000);
        }
        // ESP вообще не отвечает как модем
        return 100 + r;
    }

    // ШАГ 2. Мягкий сброс: AT+RST (как на TX — без строгой проверки текста)
    esp_clear_rx();
    esp_send_line("AT+RST\r\n");
    HAL_Delay(2000);      // ждём, пока перезагрузится
    esp_clear_rx();       // выбрасываем "ready" и логи

    // ШАГ 3. Снова "AT" после сброса
    r = esp_send_cmd("AT\r\n", "OK", 3000);
    if (r != 0) {
        return 200 + r;
    }

    // ШАГ 4. Включаем режим точки доступа (AP).
    // Делаем "best effort": пробуем CUR, потом обычный CWMODE, но НЕ вылетаем при ошибке.
    r = esp_send_cmd("AT+CWMODE_CUR=2\r\n", "OK", 5000);   // 2 = AP
    if (r != 0) {
        r = esp_send_cmd("AT+CWMODE=2\r\n", "OK", 5000);
        // Если и это не OK — не считаем фатальной ошибкой, многие прошивки уже в AP+STA
    }

    // ШАГ 5. Настраиваем свою Wi-Fi сеть:
    // SSID = "STM_RX", пароль = "12345678", канал 5, шифрование WPA2 (3)
    r = esp_send_cmd("AT+CWSAP_CUR=\"STM_RX\",\"12345678\",5,3\r\n", "OK", 10000);
    if (r != 0) {
        // Если _CUR не поддерживается, пробуем без CUR
        r = esp_send_cmd("AT+CWSAP=\"STM_RX\",\"12345678\",5,3\r\n", "OK", 10000);
        if (r != 0) {
            // без точки доступа далее смысла нет
            return 300 + r;
        }
    }

    // (опционально) можно посмотреть свой IP
    esp_send_cmd("AT+CIFSR\r\n", "OK", 5000);

    // ШАГ 6. Разрешаем несколько соединений (для сервера нужно CIPMUX=1)
    r = esp_send_cmd("AT+CIPMUX=1\r\n", "OK", 5000);
    if (r != 0) {
        return 400 + r;
    }

    // ШАГ 7. Поднимаем TCP-сервер на порту 5000
    r = esp_send_cmd("AT+CIPSERVER=1,5000\r\n", "OK", 5000);
    if (r != 0) {
        return 500 + r;
    }

    // (необязательно) можно задать таймаут соединений:
    // esp_send_cmd("AT+CIPSTO=300\r\n", "OK", 5000);

    return 0;   // ESP на RX-плате поднят как AP+TCP-сервер
}

static int recv_frame(hmac_frame_t *out, uint32_t timeout_ms)
{
    uint8_t *p = (uint8_t*)out;
    uint32_t start = HAL_GetTick();

    // 1. ждём байт 0x55, потом 0xAA
    enum { WAIT_55, WAIT_AA, READ_REST } state = WAIT_55;
    uint16_t idx = 0;

    while (HAL_GetTick() - start < timeout_ms) {
        uint8_t c;
        if (HAL_UART_Receive(&huart2, &c, 1, 50) != HAL_OK)
            continue;

        switch (state) {
        case WAIT_55:
            if (c == 0x55) {
                p[0] = c;
                state = WAIT_AA;
            }
            break;
        case WAIT_AA:
            if (c == 0xAA) {
                p[1] = c;
                idx = 2;
                state = READ_REST;
            } else {
                state = WAIT_55; // опять искать начало
            }
            break;
        case READ_REST:
            p[idx++] = c;
            if (idx >= sizeof(hmac_frame_t)) {
                // получили весь кадр
                return 0;
            }
            break;
        }
    }
    return -1; // таймаут
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
	/* USER CODE BEGIN 1 */

	/* USER CODE END 1 */

	/* MCU Configuration--------------------------------------------------------*/

	/* Reset of all peripherals, Initializes the Flash interface and the Systick. */
	HAL_Init();
	SystemClock_Config();

	rcc_config();
	gpio_config();
    systick_config();
    exti_config();
	timers_config();

	/* USER CODE BEGIN Init */
	mbedtls_memory_buffer_alloc_init(mbedtls_heap, sizeof(mbedtls_heap));
	/* USER CODE END Init */

	/* Configure the system clock */
	SystemClock_Config();

	/* USER CODE BEGIN SysInit */

	/* USER CODE END SysInit */

	/* Initialize all configured peripherals */
	MX_GPIO_Init();
	MX_TIM3_Init();
	MX_USART2_UART_Init();

	if (wifi_init_rx() != 0) {
        while(1) {
        	HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9);
			HAL_Delay(1000);
        }
	}
	/* USER CODE BEGIN 2 */

	digits_off();
	set_indicator(0);

	/* USER CODE END 2 */

	/* Infinite loop */
	/* USER CODE BEGIN WHILE */

	while (1)
	  {
	    hmac_frame_t packet;

	    if (recv_frame(&packet, 5000) == 0) {
	        if (packet.sof != SOF_WORD || packet.eof != EOF_WORD) {
	            continue;
	        }

	        if (verify_hmac_packet(&packet) == 0)
	        {
	            present_crypt_measurements(&packet);
	            if (packet.temp_c == -1) {
	                HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
	                HAL_Delay(1000);
	            } else {
	                last_t = packet.temp_c;
	                last_h = packet.hum_pc;

	                int val = (show_temp
	                    ? (int)(last_t < 0 ? 0 : (last_t > 99 ? 99 : last_t))
	                    : (int)(last_h > 99 ? 99 : last_h));

	                indicator_number = val;
	                HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9);
		            HAL_Delay(1000);
	            }
	        } else {
	            HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
	            HAL_Delay(1000);
	        }
	    }
	 }
}



/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL12;
  RCC_OscInitStruct.PLL.PREDIV = RCC_PREDIV_DIV1;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  __disable_irq();
  while (1) {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  (void)file;
  (void)line;
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
