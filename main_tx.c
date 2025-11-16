/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body (TX — DHT + ECDSA + UART)
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
#include <string.h>
#include <stdio.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/memory_buffer_alloc.h"

#include "DHT.h"   // библиотека DHT из старого проекта
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
  uint8_t  sig_len;  // длина DER подписи
} frame_hdr_t;
#pragma pack(pop)
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define SOF_WORD     0xAA55u
#define EOF_WORD     0x55AAu

// ЗАМЕНИТЕ НА СВОЙ приватный ключ (32 байта, big-endian)
static const uint8_t privkey_d[32] = {
  0xfd, 0xc5, 0xbe, 0xb0, 0x72, 0x1c, 0x64, 0x04,
  0x4f, 0x3a, 0x05, 0xc3, 0x6f, 0xdc, 0xab, 0xb8,
  0xb5, 0x97, 0xbd, 0xd1, 0xc7, 0x54, 0xa1, 0x35,
  0xf7, 0x05, 0x65, 0xde, 0xce, 0xb2, 0x86, 0x34
};

static uint8_t mbedtls_heap[6*1024];
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* Подпись DER (детерминированная ECDSA P-256) */
static int sign_der_p256(const uint8_t *msg, size_t len,
                         uint8_t *sig, size_t *sig_len)
{
  int ret;
  uint8_t hash[32];
  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);

  // Загружаем группу P-256
  if ((ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1)) != 0)
    goto out;

  // Загружаем приватный ключ d
  if ((ret = mbedtls_mpi_read_binary(&ctx.d, privkey_d, sizeof(privkey_d))) != 0)
    goto out;

  // Хешируем сообщение
  mbedtls_sha256_ret(msg, len, hash, 0);

  // Подписываем (детерминированная ECDSA по RFC 6979: RNG = NULL)
  ret = mbedtls_ecdsa_write_signature(
      &ctx,
      MBEDTLS_MD_SHA256,
      hash, sizeof(hash),
      sig, sig_len,
      NULL, NULL);

out:
  mbedtls_ecdsa_free(&ctx);
  return ret;
}
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
static uint32_t   seq = 0;

// тот самый датчик, как в старом проекте
static DHT_sensor bedRoom = { GPIOA, GPIO_PIN_7, DHT11, GPIO_PULLUP };
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

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

  // таймер нам сейчас не обязателен для DHT, но можно оставить
  HAL_TIM_Base_Start(&htim3);

  // если CubeMX не включает тактирование порта D — подстрахуемся
  __HAL_RCC_GPIOD_CLK_ENABLE();

  // светодиодом будем мигать как индикацией работы TX
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_8, GPIO_PIN_SET);
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_9, GPIO_PIN_RESET);
  /* USER CODE END 2 */

//  /* Infinite loop */
//  /* USER CODE BEGIN WHILE */
//  for(;;)
//  {
//    HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9);
//
//    // --- ЧТЕНИЕ ДАТЧИКА DHT ЧЕРЕЗ БИБЛИОТЕКУ ИЗ СТАРОГО ПРОЕКТА ---
//    DHT_data d = DHT_getData(&bedRoom);
//
//    // Библиотека возвращает -128.0f при ошибке чтения
//    if (d.temp == -128.0f || d.hum == -128.0f)
//    {
//      // Ошибка датчика — просто ждём и пробуем ещё раз
//      HAL_Delay(1000);
//      continue;
//    }
//
//    // Преобразуем float → целые значения, как в протоколе
//    int16_t  t_c  = (int16_t)(d.temp  + (d.temp  >= 0.0f ? 0.5f : -0.5f));   // округление
//    uint16_t h_pc = (uint16_t)(d.hum + 0.5f);
//
//    // --- ФОРМИРОВАНИЕ PAYLOAD ---
//    // payload: ver(1) + seq(4) + ts(4) + t(2) + h(2)
//    uint8_t payload[1 + 4 + 4 + 2 + 2];
//    size_t  off = 0;
//
//    payload[off++] = 1;  // версия протокола
//
//    uint32_t s  = ++seq;
//    uint32_t ts = HAL_GetTick();   // «время» в миллисекундах от старта
//
//    memcpy(&payload[off], &s,  4); off += 4;
//    memcpy(&payload[off], &ts, 4); off += 4;
//    memcpy(&payload[off], &t_c, 2); off += 2;
//    memcpy(&payload[off], &h_pc,2); off += 2;
//
//    // --- ПОДПИСЬ ECDSA P-256 / SHA-256 ---
//    uint8_t sig[80];
//    size_t  sig_len = 0;
//
//    if (sign_der_p256(payload, sizeof(payload), sig, &sig_len) != 0)
//    {
//      // если подпись не удалась — мигаем быстрее и пропускаем кадр
//      HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
//      HAL_Delay(500);
//      continue;
//    }
//
//    // --- ФОРМИРОВАНИЕ КАДРА ДЛЯ UART ---
//    // [SOF(2)] [payload] [sig_len(1)] [sig(sig_len)] [EOF(2)]
//    uint8_t  buf[2 + sizeof(payload) + 1 + 80 + 2];
//    size_t   w   = 0;
//    uint16_t sof = SOF_WORD;
//    uint16_t eof = EOF_WORD;
//
//    memcpy(&buf[w], &sof, 2);           w += 2;
//    memcpy(&buf[w], payload, sizeof(payload)); w += sizeof(payload);
//    buf[w++] = (uint8_t)sig_len;
//    memcpy(&buf[w], sig, sig_len);      w += sig_len;
//    memcpy(&buf[w], &eof, 2);           w += 2;
//
//    // --- ОТПРАВКА ПО UART2 ---
//    HAL_UART_Transmit(&huart2, buf, (uint16_t)w, 100);
//
//    // DHT11 по даташиту 1 Гц, но наша библиотека сама ограничивает опрос
//    HAL_Delay(2000);
//  }
  /* USER CODE END WHILE */

  /* USER CODE BEGIN 3 */
//}
///* USER CODE END 3 */

    // Светодиод на TX, чтобы видеть, что всё живо
    HAL_GPIO_WritePin(GPIOC, GPIO_PIN_8, GPIO_PIN_RESET);

    char buf[64];

    while (1)
    {
        DHT_data d = DHT_getData(&bedRoom);

        // Если датчик не отвечает, просто шлём "ERR"
        if (d.temp == -128.0f || d.hum == -128.0f) {
            const char *err = "ERR\n";
            HAL_UART_Transmit(&huart2, (uint8_t*)err, strlen(err), 100);
            HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
            HAL_Delay(1000);
            continue;
        }

        int t = (int)(d.temp + (d.temp >= 0 ? 0.5f : -0.5f));
        int h = (int)(d.hum  + 0.5f);

        // сформируем строку: "T=23 H=45\n"
        int n = snprintf(buf, sizeof(buf), "T=%d H=%d\n", t, h);
        if (n > 0) {
            HAL_UART_Transmit(&huart2, (uint8_t*)buf, (uint16_t)n, 100);
        }

        HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9);
        HAL_Delay(1000);
    }
}
//    while (1)
//    {
//        const char *test = "T=25 H=60\n";
//        HAL_UART_Transmit(&huart2, (uint8_t*)test, strlen(test), 100);
//
//        HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);  // TX жив
//        HAL_Delay(1000);
//    }
//}


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

void Error_Handler(void)
{
  __disable_irq();
  while (1)
  {
  }
}

/* USER CODE END 4 */

#ifdef  USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line)
{
  (void)file;
  (void)line;
}
#endif /* USE_FULL_ASSERT */
