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
#include "main.h"
#include "tim.h"
#include "usart.h"
#include "gpio.h"

/* USER CODE BEGIN Includes */
#include <string.h>
#include <stdio.h>

#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/memory_buffer_alloc.h"

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
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define SOF_WORD     0xAA55u
#define EOF_WORD     0x55AAu

// ЗАМЕНИТЕ НА СВОЙ приватный ключ (32 байта, big-endian)
static const uint8_t hmac_key[32] = {
  0xfd, 0xc5, 0xbe, 0xb0, 0x72, 0x1c, 0x64, 0x04,
  0x4f, 0x3a, 0x05, 0xc3, 0x6f, 0xdc, 0xab, 0xb8,
  0xb5, 0x97, 0xbd, 0xd1, 0xc7, 0x54, 0xa1, 0x35,
  0xf7, 0x05, 0x65, 0xde, 0xce, 0xb2, 0x86, 0x34
};

static uint8_t mbedtls_heap[6*1024];
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/**
 * Вычисляет HMAC-SHA256 подпись для данных
 * @param data - входные данные
 * @param data_len - длина данных
 * @param hmac - буфер для HMAC (32 байта)
 * @return 0 при успехе, иначе код ошибки
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

static int create_hmac_packet(hmac_frame_t *packet, uint32_t seq, int16_t temp, uint16_t hum)
{
    uint8_t full_hmac[32];

    // Заполняем заголовок
    packet->sof = SOF_WORD;
    packet->ver = 1;
    packet->seq = seq;
    packet->ts_ms = HAL_GetTick();
    packet->temp_c = temp;
    packet->hum_pc = hum;
    packet->eof = EOF_WORD;

    // Вычисляем HMAC для всех полей кроме SOF, HMAC и EOF
    uint8_t *data_to_sign = (uint8_t*)&packet->ver;
    size_t data_len = sizeof(hmac_frame_t) - sizeof(uint16_t) - sizeof(uint8_t[8]) - sizeof(uint16_t);

    if (compute_hmac_sha256(data_to_sign, data_len, full_hmac) != 0) {
        return -1;
    }

    // Используем только первые 8 байт HMAC для экономии трафика
    memcpy(packet->hmac, full_hmac, 8);

    return 0;
}

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
static uint32_t sequence_number = 0;
static DHT_sensor bedRoom = { GPIOA, GPIO_PIN_7, DHT11, GPIO_PULLUP };
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

#define ESP_UART huart2   // UART, который подключен к ESP-01

// Сбросить приёмник UART (выкинуть хвосты из буфера)
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

// Аналог их echoFind(): ждём, пока в ответе появится keyword
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

            // Для надёжности проверяем посимвольно на наличие keyword
            if (pos >= key_len) {
                if (strstr(buf, keyword) != NULL) {
                    return 0;   // нашли keyword
                }
            }
        }
    }
    return -1; // не нашли за timeout
}

// Аналог их SendCommand(cmd, ack): отправить команду и дождаться ack
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

// Инициализация ESP-01 на TX-плате.
// 0  -> успех, TCP-соединение с RX установлено
// !=0 -> код ошибки (по нему легко понять, на чем упали)
int wifi_init_tx(void)
{
    int r;

    // Даём модулю стабилизироваться после подачи питания
    HAL_Delay(2000);
    esp_clear_rx();

    // >>> ШАГ 1. Проверяем связь: "AT" как в их примере
    r = esp_send_cmd("AT\r\n", "OK", 3000);
    if (r != 0) {
        // Если уже здесь ошибка — ESP вообще не отвечает
        return 100 + r;
    }

    // >>> ШАГ 2. Мягкий сброс: AT+RST, как в их коде SendCommand("AT+RST", "Ready");
    r = esp_send_cmd("AT+RST\r\n", "OK", 5000);  // некоторые прошивки пишут "ready" в нижнем регистре
    if (r != 0) {
        // Если не уверены насчёт регистра, можно вместо "ready" поставить NULL и просто подождать HAL_Delay
        // Но пока пробуем так.

        return 200 + r;
    }


    // Небольшая пауза и очистка
    HAL_Delay(500);
    esp_clear_rx();

    // >>> ШАГ 3. Режим STA (клиент): AT+CWMODE=1
    r = esp_send_cmd("AT+CWMODE=1\r\n", "OK", 5000);
    if (r != 0) {
        return 300 + r;
    }


    // >>> ШАГ 4. Подключаемся к точке доступа RX-платы
    // Здесь SSID и пароль должны совпадать с тем, что ты используешь на RX-ESP (там где CWSAP).
    // Для примера: "STM_RX" и "12345678", как мы обсуждали раньше.
    r = esp_send_cmd("AT+CWJAP=\"STM_RX\",\"12345678\"\r\n", "OK", 20000);
    if (r != 0) {
        while(1) {
        	HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
        	HAL_Delay(1000);
        }
        return 400 + r;
    }

    // >>> (опционально) ШАГ 5. Проверяем IP: AT+CIFSR — как в Instructables
    esp_send_cmd("AT+CIFSR\r\n", "OK", 5000);  // можно не проверять r строго

    // >>> ШАГ 6. Один TCP-сокет: AT+CIPMUX=0
    r = esp_send_cmd("AT+CIPMUX=0\r\n", "OK", 5000);
    if (r != 0) {
        return 500 + r;
    }

    // >>> ШАГ 7. Открываем TCP-соединение к RX-ESP
    // IP 192.168.4.1 — типичный адрес точки доступа ESP в AP-режиме.
    esp_clear_rx();
    if (esp_send_line("AT+CIPSTART=\"TCP\",\"192.168.4.1\",5000\r\n") != HAL_OK) {
        return 600; // не смогли отправить команду
    }

    // Ждём "CONNECT"
    if (esp_wait_keyword("CONNECT", 10000) != 0) {

        return 610; // не получили CONNECT
    }

    // И ещё дождёмся OK (как делают в некоторых примерах)
    esp_wait_keyword("OK", 2000);
//	HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
//    HAL_Delay(500);
//	HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
//    HAL_Delay(500);

    return 0;  // Всё ОК, ESP-01 на TX-плате подключен к RX по TCP
}

// Отправка бинарного пакета через уже установленное TCP-соединение
// data/len — твой hmac_frame_t или любой буфер
// 0  -> успех
// !=0 -> код ошибки
int wifi_send_binary(const uint8_t *data, uint16_t len)
{
    char cmd[32];
    uint8_t c;
    uint32_t start;

    // Формируем команду AT+CIPSEND=<len>\r\n
    snprintf(cmd, sizeof(cmd), "AT+CIPSEND=%u\r\n", (unsigned)len);

    // Чистим приёмник перед новой командой
    esp_clear_rx();

    // Шаг 1. Отправляем AT+CIPSEND...
    if (esp_send_line(cmd) != HAL_OK) {
        return -10;   // ошибка передачи по UART
    }

    // Шаг 2. Ждём приглашения '>' от ESP
    start = HAL_GetTick();
    int got_prompt = 0;
    while (HAL_GetTick() - start < 2000)
    {
        if (HAL_UART_Receive(&ESP_UART, &c, 1, 50) == HAL_OK)
        {
            if (c == '>') {
                got_prompt = 1;
                break;
            }
        }
    }
    if (!got_prompt) {
        return -11;   // не дождались символа '>'
    }

    // Шаг 3. Отправляем сами данные (может быть чистый бинарник)
    if (HAL_UART_Transmit(&ESP_UART, (uint8_t*)data, len, 2000) != HAL_OK) {
        return -12;   // ошибка отправки полезной нагрузки
    }

    // Шаг 4. Ждём "SEND OK" от ESP
    if (esp_wait_keyword("SEND OK", 5000) != 0) {
        return -13;   // не получили подтверждение отправки
    }

    return 0; // успех
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

	if (wifi_init_tx() != 0) {
        while(1) {
        	HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9);
        	HAL_Delay(1000);
        }
	}
	/* USER CODE BEGIN 2 */

	// таймер нам сейчас не обязателен для DHT, но можно оставить
	HAL_TIM_Base_Start(&htim3);

	// если CubeMX не включает тактирование порта D — подстрахуемся
	__HAL_RCC_GPIOD_CLK_ENABLE();

	// светодиодом будем мигать как индикацией работы TX
	HAL_GPIO_WritePin(GPIOC, GPIO_PIN_8, GPIO_PIN_SET);
	HAL_GPIO_WritePin(GPIOC, GPIO_PIN_9, GPIO_PIN_RESET);
	/* USER CODE END 2 */

	// Светодиод на TX, чтобы видеть, что всё живо
	HAL_GPIO_WritePin(GPIOC, GPIO_PIN_8, GPIO_PIN_RESET);

    while (1)
    {
        DHT_data d = DHT_getData(&bedRoom);

        // Если датчик не отвечает, просто шлём "ERR"
        if (d.temp == -128.0f || d.hum == -128.0f) {
            hmac_frame_t err_packet;
            err_packet.sof = SOF_WORD;
            err_packet.ver = 1;
            err_packet.seq = sequence_number++;
            err_packet.ts_ms = HAL_GetTick();
            err_packet.temp_c = -1;  // специальное значение для ошибки
            err_packet.hum_pc = 0;
            err_packet.eof = EOF_WORD;
            memset(err_packet.hmac, 0, 8); // нулевая подпись для ошибки

            HAL_UART_Transmit(&huart2, (uint8_t*)&err_packet, sizeof(err_packet), 100);
            HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8);
            HAL_Delay(1000);
            continue;
        }

        int t = (int)(d.temp + (d.temp >= 0 ? 0.5f : -0.5f));
        int h = (int)(d.hum  + 0.5f);

        hmac_frame_t packet;
        if (create_hmac_packet(&packet, sequence_number++, t, h) == 0) {
            if (wifi_send_binary((uint8_t*)&packet, sizeof(packet)) == 0) {
                HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9); // Успешная отправка
            } else {
                HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8); // Ошибка Wi-Fi
                HAL_Delay(1000);
            }
            HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_9); // Успешная отправка
        } else {
            HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_8); // Ошибка подписи
            HAL_Delay(1000);
        }

        HAL_Delay(2000);
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
