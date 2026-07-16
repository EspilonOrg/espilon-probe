/*
 * uart_console.c - real-hardware counterpart of the virtual UART Console model.
 *
 * This firmware is a BYTE-FOR-BYTE port of conformance/console.py to C on a classic
 * ESP32. By default it drives UART2 on GPIO17(TX)/16(RX) as a raw stream - the faithful
 * "clip your own USB-TTL to the pins" gesture - and reproduces the reference model's exact
 * observable bytes (define CONSOLE_ON_UART0 to run the console on UART0/USB instead):
 *
 *   - boot: BANNER + PROMPT emitted once
 *   - per NON-terminator byte: echo it verbatim and buffer it
 *   - Enter is CR (0x0d) - a real U-Boot/boot> console, and what a terminal (screen/picocom)
 *     and probe's default `--eol cr` actually send. On CR: dispatch the accumulated line and
 *     reset the buffer. LF (0x0a) also dispatches (bare-LF tolerance). The second half of a
 *     CRLF/LFCR pair is swallowed, so a two-byte Enter dispatches exactly once.
 *   - a dispatching terminator emits "\r\n" (fresh line) in place of echoing the raw terminator
 *     byte, then the response + PROMPT. CR/LF never enter the line buffer.
 *
 * The console runs on the raw UART driver (uart_read_bytes/uart_write_bytes), NOT on
 * stdio/VFS, so there is NO CRLF translation, NO cooked echo, and NO log interleaving:
 * the line carries only the console protocol bytes. On the default UART2 path the mask-ROM
 * boot log (which is on UART0) does not even reach the console line; it only applies to the
 * CONSOLE_ON_UART0 variant. See README.md for the model spec and the wiring.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Console UART.
 *   UART2 on GPIO pins  -> faithful setup: probe the target with your own USB-TTL
 *                          adapter clipped onto the pins (real hardware gesture).
 *   UART0 (USB port)    -> one-cable convenience variant (define CONSOLE_ON_UART0).
 * Default: UART2. */
#ifdef CONSOLE_ON_UART0
#define CONSOLE_UART    UART_NUM_0
#else
#define CONSOLE_UART    UART_NUM_2
#define CONSOLE_TX_GPIO 17   /* ESP32 TX -> connect to USB-TTL RX */
#define CONSOLE_RX_GPIO 16   /* ESP32 RX -> connect to USB-TTL TX */
#endif
#define UART_RX_BUF  1024
#define READ_CHUNK   256
#define LINE_MAX     2048

/* Mirror console.py exactly (byte-for-byte). */
static const char BANNER[] = "=== espilon uart console (pilot) ===\r\n";
static const char PROMPT[] = "boot> ";
static const char EOL[]    = "\r\n";

/* Partial-line buffer across reads, the C analogue of Console._line (a real UART FIFO). */
static uint8_t s_line[LINE_MAX];
static size_t  s_line_len = 0;

/* The terminator just dispatched ('\r'/'\n', or 0), the C analogue of Console._prev_term:
   used to swallow the second half of a CRLF/LFCR pair so a two-byte Enter dispatches once. */
static uint8_t s_prev_term = 0;

static inline void tx(const void *data, size_t len)
{
    if (len) {
        uart_write_bytes(CONSOLE_UART, (const char *)data, len);
    }
}

static inline void tx_str(const char *s)
{
    tx(s, strlen(s));
}

/* Python bytes.strip() whitespace set: space, \t, \n, \r, \v, \f. */
static inline int is_py_ws(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static inline int eq(const uint8_t *p, size_t n, const char *lit)
{
    return n == strlen(lit) && memcmp(p, lit, n) == 0;
}

/*
 * Port of Console._dispatch(line): line is the accumulated bytes. CR/LF are consumed as
 * terminators by feed() and never buffered, so the line carries no stray CR/LF.
 *
 *   cmd, _, arg = line.partition(b" ")   # split on FIRST space only
 *   cmd = cmd.strip()                    # arg is NOT stripped
 */
static void dispatch(const uint8_t *line, size_t n)
{
    /* partition on the first space */
    const uint8_t *cmd = line;
    size_t cmd_len = n;
    const uint8_t *arg = line + n;
    size_t arg_len = 0;
    for (size_t i = 0; i < n; i++) {
        if (line[i] == ' ') {
            cmd_len = i;
            arg = line + i + 1;
            arg_len = n - i - 1;
            break;
        }
    }

    /* cmd.strip() - leading and trailing Python-whitespace */
    while (cmd_len > 0 && is_py_ws(cmd[0])) { cmd++; cmd_len--; }
    while (cmd_len > 0 && is_py_ws(cmd[cmd_len - 1])) { cmd_len--; }

    if (cmd_len == 0) {
        tx_str(PROMPT);
        return;
    }
    if (eq(cmd, cmd_len, "help")) {
        tx_str("commands: help printenv echo <text>\r\n");
    } else if (eq(cmd, cmd_len, "printenv")) {
        tx_str("bootcmd=run distro_bootcmd\r\nbaudrate=115200\r\nver=pilot-1\r\n");
    } else if (eq(cmd, cmd_len, "echo")) {
        tx(arg, arg_len);
        tx_str(EOL);
    } else {
        tx_str("unknown command: ");
        tx(cmd, cmd_len);
        tx_str(EOL);
    }
    tx_str(PROMPT);
}

/*
 * Port of Console.feed(data): CR (0x0d) is the line terminator (Enter on a real terminal and
 * probe's default `--eol cr`); LF (0x0a) also dispatches. On a dispatching terminator, emit
 * "\r\n" (echo is on) in place of the raw terminator byte, then dispatch the accumulated line
 * and reset the buffer - exactly as `out += EOL; ... out += self._dispatch(...)`. The second
 * half of a CRLF/LFCR pair is swallowed via s_prev_term so Enter dispatches once. Non-terminator
 * bytes are echoed verbatim and buffered; CR/LF never enter the buffer.
 */
static void feed(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        if (b == '\r' || b == '\n') {
            if (s_prev_term != 0 && b != s_prev_term) {
                s_prev_term = 0;            /* pair consumed; the next terminator dispatches */
                continue;
            }
            tx_str(EOL);                    /* echo is on: Enter -> fresh line, not the raw byte */
            dispatch(s_line, s_line_len);
            s_line_len = 0;
            s_prev_term = b;
        } else {
            tx(&b, 1);                      /* echo (self.echo is True) */
            if (s_line_len < LINE_MAX) {
                s_line[s_line_len++] = b;
            }
            s_prev_term = 0;
            /* If the line exceeds LINE_MAX the model's buffer is unbounded; the conformance
             * tape lines are short, so overflow bytes are dropped from the buffer only (echo
             * still happens). See README deviation note. */
        }
    }
}

void app_main(void)
{
    const uart_config_t cfg = {
        .baud_rate  = 115200,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    /* Own the console UART directly (UART2 on GPIO17/16 by default, UART0/USB when
       CONSOLE_ON_UART0): blocking TX (tx buffer 0), RX FIFO buffered. */
    ESP_ERROR_CHECK(uart_driver_install(CONSOLE_UART, UART_RX_BUF, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(CONSOLE_UART, &cfg));
#ifndef CONSOLE_ON_UART0
    /* Route UART2 to the GPIO pins; clip your USB-TTL adapter here (TX17/RX16/GND). */
    ESP_ERROR_CHECK(uart_set_pin(CONSOLE_UART, CONSOLE_TX_GPIO, CONSOLE_RX_GPIO,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
#else
    /* UART0 uses the default USB-serial pins (TXD0/RXD0); no uart_set_pin needed. */
#endif

    /* Boot banner: BANNER + PROMPT, exactly Console.banner(). */
    tx_str(BANNER);
    tx_str(PROMPT);

    uint8_t buf[READ_CHUNK];
    for (;;) {
        int n = uart_read_bytes(CONSOLE_UART, buf, sizeof(buf), pdMS_TO_TICKS(20));
        if (n > 0) {
            feed(buf, (size_t)n);
        }
    }
}
