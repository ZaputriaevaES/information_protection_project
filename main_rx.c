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
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
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
static const uint8_t pubkey65[65] = {
    0x04, 0xf4, 0x26, 0x16, 0x27, 0x3a, 0x1e, 0xbc, 0xba, 0x52, 0xe6, 0x7c,
    0xc8, 0xa6, 0xf3, 0x46, 0x8c, 0x97, 0xac, 0xbc, 0x3a, 0x07, 0x41, 0x79,
    0x12, 0xf3, 0x27, 0xfb, 0x7b, 0x18, 0xaa, 0x0f, 0xca, 0x51, 0x39, 0x29,
    0x0e, 0x67, 0x00, 0x8f, 0xf1, 0x46, 0xe6, 0x7a, 0x5b, 0xac, 0x5e, 0x85,
    0xbc, 0xe2, 0x30, 0x10, 0x6c, 0xa8, 0xb2, 0xb8, 0xd8, 0x29, 0x49, 0x70,
    0xb7, 0x97, 0x36, 0x28, 0xcc
};
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
static volatile uint8_t disp_left = 0, disp_right = 0, which = 0;
static inline void set_display_uint(uint8_t v)
{
    disp_left  = v / 10;
    disp_right = v % 10;
}
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

//static int start_count = 0;
//static int tim2_counter = 0;
//
//
//static int sysytick_counter_top  = 4;
//static int delay_counter_top = 0;
//static int ms = 0; //0.....1000
//static int ms_old = 0;
//
//static int sysytick_counter = 0;
//static int delay_counter = 0;
//
//static int  indicator_number = 1000;


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

//static char show_temp = 0;

void EXTI0_1_IRQHandler(void)
{

    /*
     * Если разница больше чем 50 между ms_old и ms, то выполнить действие
     */

     if((ms - ms_old) > 50)
     {
     	//LL_GPIO_TogglePin(GPIOC, LL_GPIO_PIN_9);
    	 show_temp = (show_temp + 1)%2;
     }

    /*
     * Обновить значение old_ms и сбросить флаг нулевой линии прерывания
     */

    ms_old = ms;

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
     * For simplicity there are only decoded values for the first 4 numbers
     */
    static const uint32_t decoder[] = {
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | \
        LL_GPIO_PIN_4 | LL_GPIO_PIN_5, 						// 0
        LL_GPIO_PIN_1 | LL_GPIO_PIN_2, 						// 1
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_6 | LL_GPIO_PIN_4 | \
        LL_GPIO_PIN_3, 								// 2
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_6 | LL_GPIO_PIN_2 | \
        LL_GPIO_PIN_3, 								// 3
        LL_GPIO_PIN_5 | LL_GPIO_PIN_6 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2, 		// 4
        LL_GPIO_PIN_0 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | LL_GPIO_PIN_5 | \
        LL_GPIO_PIN_6, 								// 5
        LL_GPIO_PIN_0 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | LL_GPIO_PIN_4 | \
        LL_GPIO_PIN_5 | LL_GPIO_PIN_6, 						// 6
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2, 				// 7
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | \
        LL_GPIO_PIN_4 | LL_GPIO_PIN_5 | LL_GPIO_PIN_6, 				// 8
        LL_GPIO_PIN_0 | LL_GPIO_PIN_1 | LL_GPIO_PIN_2 | LL_GPIO_PIN_3 | \
        LL_GPIO_PIN_5 | LL_GPIO_PIN_6, 						// 9
    };
    const uint8_t max_num = sizeof(decoder) / sizeof(uint32_t);
    uint32_t port_state = 0;

    /*
     * Read current state and do not change pins that are not related to
     * indicator (that is done by using masking)
     */
    port_state = LL_GPIO_ReadOutputPort(GPIOB);
    /*
     * Example:
     * 01100101 <= Input
     * mask = 111 (pins allowed to be changed)
     * ~mask = 11111000 (inverted mask sets remaing bits to one)
     * result = result & ~mask (zero only first three bits)
     * result = result | 001 (modify first three bits)
     * result -> 01100001
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


static int verify_der_p256(const uint8_t *msg, size_t len,
                           const uint8_t *sig_der, size_t sig_len)
{
  int ret;
  uint8_t hash[32];
  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);

  if ((ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1)) != 0)
    goto out;
  if ((ret = mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q,
                                           pubkey65, sizeof(pubkey65))) != 0)
    goto out;

  mbedtls_sha256_ret(msg, len, hash, 0);
  ret = mbedtls_ecdsa_read_signature(&ctx, hash, sizeof(hash),
                                     sig_der, sig_len);
out:
  mbedtls_ecdsa_free(&ctx);
  return ret;
}

static HAL_StatusTypeDef uart_recv_exact(uint8_t *buf, uint16_t len,
                                         uint32_t timeout_ms)
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

//void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
//{
//    if (htim->Instance == TIM3)
//    {
//        digits_off();
//        if (which == 0) {
//            set_indicator(disp_left);
//            digit_on(GPIO_PIN_10);   // первый разряд
//            which = 1;
//        } else {
//            set_indicator(disp_right);
//            digit_on(GPIO_PIN_11);   // второй разряд
//            which = 0;
//        }
//        // НЕ меняем disp_left/disp_right здесь
//    }
//}
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
  timers_config();

  /* USER CODE BEGIN Init */
  // Инициализация аллокатора mbedTLS
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
  /* USER CODE BEGIN 2 */
  // Запускаем таймер для мультиплексирования индикатора (TIM3 -> 1 кГц)
  // HAL_TIM_Base_Start_IT(&htim3);

  // Погасить всё и показать "00" по умолчанию
  digits_off();
  set_indicator(0);
  set_display_uint(0);
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
//  while (1)
//  {
//    // Можно мигать светодиодом, чтобы видеть, что RX жив
//    HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9);
//
//    // --- Поиск начала кадра (SOF = 0xAA55) ---
//    // найти SOF (читаем сразу 2 байта как слово)
//          uint16_t sof = 0;
//          do {
//            if (uart_recv_exact((uint8_t*)&sof, 2, 5000) != HAL_OK)
//              continue;                  // ждём дальше
//          } while (sof != SOF_WORD);     // SOF_WORD = 0xAA55
//
//    // --- Чтение payload: ver(1) + seq(4) + ts(4) + temp(2) + hum(2) ---
//    uint8_t payload[1 + 4 + 4 + 2 + 2];
//    if (uart_recv_exact(payload, sizeof(payload), 50) != HAL_OK)
//      continue;
//
//    // --- Длина и тело подписи ---
//    uint8_t sig_len = 0;
//    if (uart_recv_exact(&sig_len, 1, 50) != HAL_OK)
//      continue;
//    if (sig_len == 0 || sig_len > 80)
//      continue;
//
//    uint8_t sig[80];
//    if (uart_recv_exact(sig, sig_len, 100) != HAL_OK)
//      continue;
//
//
//    // --- Контроль EOF ---
//    uint8_t eof_bytes[2];
//    if (uart_recv_exact(eof_bytes, 2, 50) != HAL_OK)
//      continue;
//    uint16_t eof = (uint16_t)(eof_bytes[0] | ((uint16_t)eof_bytes[1] << 8));
//    if (eof != EOF_WORD)
//      continue;
//
////    // --- Проверка подписи ---
////    if (verify_der_p256(payload, sizeof(payload), sig, sig_len) != 0) {
////      // Неверная подпись — мигаем другим светодиодом (PC8)
////      HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
////      continue;
////    }
//
//    // --- Парсинг полезной нагрузки ---
//    uint8_t  ver  = payload[0];
//    (void)ver; // пока версия не используется
//
//    uint32_t seq = 0;
//    memcpy(&seq, &payload[1], 4);
//
//    uint32_t ts  = 0;
//    memcpy(&ts, &payload[5], 4);
//
//    int16_t  t_c = 0;
//    memcpy(&t_c, &payload[9], 2);
//
//    uint16_t h_p = 0;
//    memcpy(&h_p, &payload[11], 2);
//
//    // Сохраняем последние значения для отображения
//    last_t = t_c;
//    last_h = h_p;
//
//    // Немедленно обновим то, что сейчас показываем (температура или влажность)
//    uint8_t val = (show_temp
//                   ? (uint8_t)(t_c < 0 ? 0 : (t_c > 99 ? 99 : t_c))
//                   : (uint8_t)(h_p > 99 ? 99 : h_p));
//    set_display_uint(val);
//  }
//    /* USER CODE END WHILE */
//
//    /* USER CODE BEGIN 3 */
//  }
//  /* USER CODE END 3 */

  	 char line[64];
     uint8_t idx = 0;

//     indicator_number = 1234;
//     set_all_indicators(indicator_number);

     HAL_Delay(1000);

     while (1)
     {
         uint8_t b;
         if (HAL_UART_Receive(&huart2, &b, 1, 100) == HAL_OK)
         {
             if (b == '\n' || b == '\r')        // конец строки
             {
                 if (idx == 0) {
                     // пустая строка — игнорируем
                     continue;
                 }

                 line[idx] = '\0';
                 idx = 0;

                 int t = 0, h = 0;

                 // пробуем распарсить "T=23 H=45"
                 if (sscanf(line, "T=%d H=%d", &t, &h) == 2)
                 {
                     if (t < 0)    t = 0;
                     if (t > 9999) t = 9999;

                     indicator_number = t;   // TIM2_IRQHandler сам обновит индикацию

                     // успешный кадр — мигнём PC9
                     HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9);
                 }
                 else if (strcmp(line, "ERR") == 0)
                 {
                     // с TX пришло "ERR" → датчик не ответил
                     HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
                 }
                 else
                 {
                     // какая-то непонятная строка
                     HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
                 }
             }
             else
             {
                 // накапливаем символы до конца строки
                 if (idx < sizeof(line) - 1)
                 {
                     line[idx++] = b;
                 }
                 else
                 {
                     // переполнение буфера — сброс
                     idx = 0;
                 }
             }
         }

         // без HAL_Delay() тут — UART и так блокирующий
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

/* USER CODE BEGIN 4 */
//void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
//{
//  if (htim->Instance == TIM3) {
//    static uint32_t tick = 0;
//
//    // мультиплексирование двух разрядов
//    digits_off();
//    if (which == 0) {
//      set_indicator(disp_left);
//      digit_on(GPIO_PIN_10);
//      which = 1;
//    } else {
//      set_indicator(disp_right);
//      digit_on(GPIO_PIN_11);
//      which = 0;
//    }
//
//    // раз в секунду переключаемся между температурой и влажностью
//    if (++tick >= 1000) {
//      tick = 0;
//      show_temp ^= 1;
//
//      uint8_t v = (show_temp
//                   ? (uint8_t)(last_t < 0 ? 0 : (last_t > 99 ? 99 : last_t))
//                   : (uint8_t)(last_h > 99 ? 99 : last_h));
//      set_display_uint(v);
//    }
//  }
//}
/* USER CODE END 4 */

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
