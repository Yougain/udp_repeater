#define _POSIX_C_SOURCE 200809L

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htobe64(x) __bswap_64 (x)
#  define htole64(x) __uint64_identity (x)
#  define be64toh(x) __bswap_64 (x)
#  define le64toh(x) __uint64_identity (x)
# else
#  define htobe64(x) __uint64_identity (x)
#  define htole64(x) __bswap_64 (x)
#  define be64toh(x) __uint64_identity (x)
#  define le64toh(x) __bswap_64 (x)
# endif


#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h> // getaddrinfoを使用するために必要
#include <stdint.h> // uint32_tを使用するために必要
#include <pthread.h> // スレッドを使用するために必要
#include <time.h>    // UNIX時刻を取得するために必要
#include <sys/time.h>
#include <stdarg.h>
#include <errno.h> // For program_invocation_short_name
#include <libgen.h> // For program_invocation_short_name
#include <sys/stat.h>  // stat, mkdir関数のために必要
#include <sys/types.h> // stat構造体のために必要

uint64_t program_start_time = 0; // プログラムの起動時刻を格納する変数
pid_t program_pid = 0; // プログラムのプロセスIDを格納する変数
uint64_t peer_program_start_time = 0; // 相手側プログラムの起動時刻を格納する変数
pid_t peer_program_pid = 0; // 相手側プログラムのプロセスIDを格納する変数

uint64_t get_process_start_time(pid_t pid) {
    char stat_path[64];
    char buffer[256];
    FILE *stat_file;
    uint64_t starttime;
    uint64_t btime;
    uint64_t clk_tck = sysconf(_SC_CLK_TCK);

    // /proc/[PID]/stat のパスを作成
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

    // /proc/[PID]/stat を開く
    stat_file = fopen(stat_path, "r");
    if (!stat_file) {
        perror("Failed to open /proc/[PID]/stat");
        return 0;
    }

    // ファイルを読み取る
    if (fgets(buffer, sizeof(buffer), stat_file) == NULL) {
        perror("Failed to read /proc/[PID]/stat");
        fclose(stat_file);
        return 0;
    }
    fclose(stat_file);

    // 22番目のフィールド（starttime）を取得
    char *token = strtok(buffer, " ");
    for (int i = 1; i < 22; i++) {
        token = strtok(NULL, " ");
    }
    starttime = atol(token);

    // /proc/stat から btime を取得
    stat_file = fopen("/proc/stat", "r");
    if (!stat_file) {
        perror("Failed to open /proc/stat");
        return 0;
    }

    while (fgets(buffer, sizeof(buffer), stat_file)) {
        if (strncmp(buffer, "btime", 5) == 0) {
            btime = atol(buffer + 6);
            break;
        }
    }
    fclose(stat_file);

    // プロセスの起動時刻を計算
    uint64_t start_time_seconds = btime + (starttime / clk_tck);

    // 起動時刻を表示
    return start_time_seconds;
}


// MD5のコンテキスト構造体
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
} MD5_CTX;

// MD5の補助関数
void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen);
void MD5Final(unsigned char digest[16], MD5_CTX *context);
void MD5Transform(uint32_t state[4], const unsigned char block[64]);
void Encode(unsigned char *output, const uint32_t *input, unsigned int len);
void Decode(uint32_t *output, const unsigned char *input, unsigned int len);
void MD5_memcpy(unsigned char *output, const unsigned char *input, unsigned int len);
void MD5_memset(unsigned char *output, int value, unsigned int len);

// Base63エンコード用の文字セット
const char BASE63_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

// Base63エンコード関数
void base63_encode(const unsigned char *input, size_t input_len, char *output, size_t output_len) {
    uint32_t buffer = 0;
    int bits_in_buffer = 0;
    size_t output_index = 0;

    for (size_t i = 0; i < input_len; i++) {
        buffer = (buffer << 8) | input[i];
        bits_in_buffer += 8;

        while (bits_in_buffer >= 6) {
            if (output_index >= output_len - 1) {
                break; // 出力バッファが不足している場合
            }
            output[output_index++] = BASE63_CHARS[(buffer >> (bits_in_buffer - 6)) & 0x3F];
            bits_in_buffer -= 6;
        }
    }

    if (bits_in_buffer > 0 && output_index < output_len - 1) {
        output[output_index++] = BASE63_CHARS[(buffer << (6 - bits_in_buffer)) & 0x3F];
    }

    output[output_index] = '\0'; // 終端文字を追加
}

// MD5を計算し、Base63でエンコードした最初の6文字を取得する関数
char* md5_6(const char *data, size_t len) {
    static char output[7];
    char digest[16];
    MD5_CTX context;

    MD5Init(&context);
    MD5Update(&context, (char *)data, len);
    MD5Final(digest, &context);

    // Base63エンコード
    base63_encode(digest, 16, output, 7); // 最初の6文字 + 終端文字
    return output;
}

// MD5の初期化
void MD5Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

// MD5の更新
void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen) {
    unsigned int i, index, partLen;

    index = (unsigned int)((context->count[0] >> 3) & 0x3F);
    if ((context->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
        context->count[1]++;
    context->count[1] += ((uint32_t)inputLen >> 29);

    partLen = 64 - index;

    if (inputLen >= partLen) {
        MD5_memcpy(&context->buffer[index], input, partLen);
        MD5Transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
            MD5Transform(context->state, &input[i]);

        index = 0;
    } else {
        i = 0;
    }

    MD5_memcpy(&context->buffer[index], &input[i], inputLen - i);
}

// MD5の最終処理
void MD5Final(unsigned char digest[16], MD5_CTX *context) {
    unsigned char bits[8];
    unsigned int index, padLen;

    Encode(bits, context->count, 8);

    index = (unsigned int)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, (unsigned char *)"\x80", 1);
    MD5Update(context, (unsigned char *)"\0\0\0\0\0\0\0", padLen - 1);
    MD5Update(context, bits, 8);

    Encode(digest, context->state, 16);

    MD5_memset((unsigned char *)context, 0, sizeof(*context));
}

// MD5の補助マクロ
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

void MD5Transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a, b, c, d, x[16];

    // 入力ブロックを32ビットワードにデコード
    for (int i = 0, j = 0; j < 64; i++, j += 4) {
        x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j + 1]) << 8) |
               (((uint32_t)block[j + 2]) << 16) | (((uint32_t)block[j + 3]) << 24);
    }

    // 現在の状態を保存
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

    // ラウンド1
    FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    // ラウンド2
    GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], S22, 0x02441453); /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    // ラウンド3
    HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[6], S34, 0x04881d05); /* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

    // ラウンド4
    II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

    // 状態を更新
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // セキュリティのために一時変数をクリア
    memset(x, 0, sizeof(x));
}

void Encode(unsigned char *output, const uint32_t *input, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xff);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

void Decode(uint32_t *output, const unsigned char *input, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
                    (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
    }
}

void MD5_memcpy(unsigned char *output, const unsigned char *input, unsigned int len) {
    memcpy(output, input, len);
}

void MD5_memset(unsigned char *output, int value, unsigned int len) {
    memset(output, value, len);
}


// グローバル変数
FILE *log_file = NULL;
const char* program_invocation_short_name = NULL;
const char *log_path = "~/.log/udp_repeater.log";
char resolved_log_path[256];


void resolve_path(const char *path, char *resolved_path, size_t size) {
    if (path[0] == '~') {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(resolved_path, size, "%s/%s", home, path + 2);
        } else {
            fprintf(stderr, "Error: HOME environment variable is not set.\n");
            exit(EXIT_FAILURE);
        }
    } else {
        snprintf(resolved_path, size, "%s", path);
    }
}


// ログ出力用関数
void log_message(const char *file, const uint32_t line, const char *format, ...) {
    if (!log_file){
        // ログディレクトリを作成
        const char *log_dir = "~/.log";
        char resolved_log_dir[256];
        resolve_path(log_dir, resolved_log_dir, sizeof(resolved_log_dir));
        struct stat st;
        if (stat(resolved_log_dir, &st) != 0) {
            if (mkdir(resolved_log_dir, 0755) < 0) {
                fprintf(stderr, "Error: Could not create log directory %s: %s\n", resolved_log_dir, strerror(errno));
                exit(EXIT_FAILURE);
            }
        }

        // ログファイルをオープン
        resolve_path(log_path, resolved_log_path, sizeof(resolved_log_path));
        log_file = fopen(resolved_log_path, "a");
        if (!log_file) {
            fprintf(stderr, "Error: Could not open log file %s: %s\n", resolved_log_path, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    // ファイルサイズをチェック
    fseek(log_file, 0, SEEK_END);
    long file_size = ftell(log_file);
    if (file_size > 110 * 1024 * 1024) { // 110MBを超えた場合
        fclose(log_file);

        // 一時ファイルを作成して最初の10MBを削除
        FILE *temp_file = fopen("/tmp/udp_repeater_temp.log", "w");
        if (!temp_file) {
            fprintf(stderr, "Error: Could not create temporary log file.\n");
            return;
        }

        log_file = fopen(resolved_log_path, "r");
        if (!log_file) {
            fprintf(stderr, "Error: Could not reopen log file for trimming.\n");
            fclose(temp_file);
            return;
        }

        fseek(log_file, 10 * 1024 * 1024, SEEK_SET); // 10MB分スキップ
        char buffer[4096];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), log_file)) > 0) {
            fwrite(buffer, 1, bytes_read, temp_file);
        }

        fclose(log_file);
        fclose(temp_file);

        // 元のログファイルを置き換え
        remove(resolved_log_path);
        rename("/tmp/udp_repeater_temp.log", resolved_log_path);

        // 再オープン
        log_file = fopen("~/.log/udp_repeater.log", "a");
        if (!log_file) {
            fprintf(stderr, "Error: Could not reopen log file after trimming.\n");
            return;
        }
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    //puts(format);

    // ミリ秒単位の時刻を計算
    struct tm *tm_info = localtime(&tv.tv_sec);
    char time_buffer[64];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    long milliseconds = tv.tv_usec / 1000;

    // プロセス名とプロセス番号を取得
    char process_name[256];
    snprintf(process_name, sizeof(process_name), "%s", program_invocation_short_name);
    pid_t pid = getpid();

    // ログメッセージをフォーマット
    va_list args, args_copy;
    va_start(args, format);
    fprintf(log_file, "%s.%03ld %s[%d] ", time_buffer, milliseconds, process_name, pid);
    fprintf(stderr, "%s.%03ld %s[%d] ", time_buffer, milliseconds, process_name, pid);
    fprintf(log_file, "%s:%d ", file, line);
    fprintf(stderr, "%s:%d ", file, line);
    char buff[4096];
    vsnprintf(buff, 4096, format, args);
    fputs(buff, stderr);
    fputs(buff, log_file);
    fprintf(log_file, "\n");
    fprintf(stderr, "\n");
    va_end(args);

    fflush(log_file); // ログを即時書き込み
}

void print_sockaddr(const struct sockaddr *addr) {
    char ip_str[INET6_ADDRSTRLEN]; // IPv4とIPv6の両方に対応
    uint16_t port;

    if (addr->sa_family == AF_INET) {
        // IPv4の場合
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, sizeof(ip_str));
        port = ntohs(addr_in->sin_port);
        fprintf(stderr, "IPv4 Address: %s, Port: %u\n", ip_str, port);
    } else if (addr->sa_family == AF_INET6) {
        // IPv6の場合
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip_str, sizeof(ip_str));
        port = ntohs(addr_in6->sin6_port);
        fprintf(stderr, "IPv6 Address: %s, Port: %u\n", ip_str, port);
    } else {
        fprintf(stderr, "Unknown address family: %d\n", addr->sa_family);
    }
}

//#define LOG_MESSAGE(format, ...) \
//    log_message(__FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_AND_EXIT(format, ...) \
    (log_message(__FILE__, __LINE__, format, ##__VA_ARGS__), exit(EXIT_FAILURE))
#define LOG_MESSAGE(format, ...)


// URLを解析してホスト名、パス、ポート番号を抽出する関数
int parse_url(const char *url, char *hostname, char *path, uint16_t *port) {
    char temp_url_buff[256];
    strncpy(temp_url_buff, url, sizeof(temp_url_buff) - 1);
    temp_url_buff[sizeof(temp_url_buff) - 1] = '\0';
    char *temp_url = temp_url_buff;

    // URLの形式を確認
    if (strncmp(temp_url, "http://", 7) == 0) {
        temp_url += 7; // "http://"をスキップ
    } else if (strncmp(temp_url, "https://", 8) == 0) {
        LOG_MESSAGE("Error: HTTPS is not supported in this implementation.");
        return -1;
    }

    // ホスト名とポート番号を抽出
    char *host_end = strchr(temp_url, '/');
    if (host_end) {
        *host_end = '\0'; // ホスト名の終端を設定
        strncpy(path, host_end + 1, 256); // パスをコピー
    } else {
        path[0] = '\0'; // パスがない場合は空文字列
    }

    char *port_start = strchr(temp_url, ':');
    if (port_start) {
        *port_start = '\0'; // ホスト名の終端を設定
        *port = atoi(port_start + 1); // ポート番号を取得
    } else {
        *port = 80; // デフォルトのHTTPポート
    }

    strncpy(hostname, temp_url, 256); // ホスト名をコピー
    return 0;
}

void get_url(char *hostname, char *path, uint16_t port) {
    int sock;
    struct addrinfo hints, *res, *rp;
    const int BUFFER_SIZE = 4096; // バッファサイズ
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    // addrinfo構造体を初期化
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;       // IPv4とIPv6の両方を許可
    hints.ai_socktype = SOCK_STREAM;   // TCP

    // ポート番号を文字列に変換
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    // ホスト名を解決
    if (getaddrinfo(hostname, port_str, &hints, &res) != 0) {
        LOG_MESSAGE("Error resolving hostname: %s", strerror(errno));
        return;
    }

    // IPv4を優先してアドレスを選択
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
            sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sock < 0) {
                LOG_MESSAGE("Error creating socket: %s", strerror(errno));
                continue; // 次のアドレスを試す
            }

            // サーバーに接続
            if (connect(sock, rp->ai_addr, rp->ai_addrlen) < 0) {
                LOG_MESSAGE("Error connecting to server: %s", strerror(errno));
                close(sock); // 接続失敗時はソケットを閉じる
                continue;
            }

            break; // 接続成功
        }
    }

    if (rp == NULL) {
        LOG_MESSAGE("Error: get_url: Could not connect to any address for %s", hostname);
        freeaddrinfo(res);
        return;
    }

    // addrinfoのメモリを解放
    freeaddrinfo(res);

    // HTTP GETリクエストを作成
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, hostname);

    // リクエストを送信
    if (send(sock, request, strlen(request), 0) < 0) {
        LOG_MESSAGE("Error sending request: %s", strerror(errno));
        close(sock);
        return;
    }

    // レスポンスを受信
    ssize_t bytes_received;
    while ((bytes_received = recv(sock, response, sizeof(response) - 1, 0)) > 0) {
        response[bytes_received] = '\0'; // NULL終端
        LOG_MESSAGE("Response of %s:%u/%s: %s", hostname, port, path, response);         // レスポンスを出力
    }

    // レスポンス受信時のエラー
    if (bytes_received < 0) {
        LOG_MESSAGE("Error receiving response: %s", strerror(errno));
    }

    // ソケットを閉じる
    close(sock);
}

// URL情報を渡すための構造体
typedef struct {
    char hostname[256];
    char path[256];
    uint16_t port;
} UrlInfo;

// スレッドで実行する関数
void *get_url_thread(void *arg) {
    UrlInfo *url_info = (UrlInfo *)arg;

    // URLを取得
    get_url(url_info->hostname, url_info->path, url_info->port);

    free(url_info); // メモリを解放
    return NULL;
}

/* IAX フレームタイプ定数 */
#define IAX_FRAMETYPE_CONTROL     0x04   /* Control Frame */
#define IAX_FRAMETYPE_IAX         0x06   /* IAX Control Frame */

/* IAX サブクラス定数 */
#define IAX_SUBCLASS_NEW          0x01   /* NEW - 新規呼制御 */
#define IAX_SUBCLASS_RINGING      0x04   /* RINGING - 呼出中 */

/* IAX 情報要素タイプ ID */
#define IAX_IE_CALLED_NUMBER      0x01   /* 着信先番号 */
#define IAX_IE_CALLING_NUMBER     0x02   /* 発信元番号 */
#define IAX_IE_CALLING_NAME       0x04   /* 発信者名 */

#define IAX_DEFAULT_PORT          4569   /* IAX デフォルトポート */
#define MAX_PACKET_SIZE           1024   /* 受信バッファサイズ */

/* パケットから特定のビットを抽出する */
#define GET_BIT(data, bit) (((data) >> (bit)) & 0x01)

/* IAX パケットヘッダー解析用の構造体 */
typedef struct {
    uint8_t f_bit;                  /* F ビット（1=Full Frame） */
    uint16_t source_call_number;    /* 送信元コール番号 */
    uint8_t r_bit;                  /* R ビット（再送フラグ） */
    uint16_t dest_call_number;      /* 送信先コール番号 */
    uint32_t timestamp;             /* タイムスタンプ */
    uint8_t oseqno;                 /* 送信シーケンス番号 */
    uint8_t iseqno;                 /* 受信シーケンス番号 */
    uint8_t frametype;              /* フレームタイプ */
    uint8_t c_bit;                  /* C ビット（サブクラス解釈） */
    uint8_t subclass;               /* サブクラス（下位7ビット） */
} iax_full_header_t;

/* 情報要素の解析結果を格納 */
typedef struct {
    char called_number[64];         /* 着信先番号 */
    char calling_number[64];        /* 発信元番号 */
    char calling_name[64];          /* 発信者名 */
} iax_call_info_t;

/* IAX Full Frameヘッダーを解析 */
void parse_iax_full_header(const unsigned char *packet, iax_full_header_t *header) {
    uint16_t first_word, second_word;
    
    /* 最初の2バイトを解析 */
    first_word = (packet[0] << 8) | packet[1];
    header->f_bit = (first_word >> 15) & 0x01;
    header->source_call_number = first_word & 0x7FFF;
    
    /* 次の2バイトを解析 */
    second_word = (packet[2] << 8) | packet[3];
    header->r_bit = (second_word >> 15) & 0x01;
    header->dest_call_number = second_word & 0x7FFF;
    
    /* タイムスタンプ (4バイト) */
    header->timestamp = (packet[4] << 24) | (packet[5] << 16) | 
                        (packet[6] << 8) | packet[7];
    
    /* シーケンス番号 */
    header->oseqno = packet[8];
    header->iseqno = packet[9];
    
    /* フレームタイプとサブクラス */
    header->frametype = packet[10];
    header->c_bit = (packet[11] >> 7) & 0x01;
    header->subclass = packet[11] & 0x7F;
}

/* 情報要素（IE）をパースする */
void parse_information_elements(const unsigned char *data, int data_len, iax_call_info_t *info) {
    int pos = 0;
    
    /* デフォルト値の設定 */
    memset(info, 0, sizeof(iax_call_info_t));
    
    while (pos < data_len - 2) { /* IE タイプ+長さで最低2バイト必要 */
        uint8_t ie_type = data[pos++];
        uint8_t ie_length = data[pos++];
        
        /* バッファオーバーフローチェック */
        if (pos + ie_length > data_len) {
            LOG_MESSAGE("Warning: IE length exceeds packet bounds");
            break;
        }
        
        /* 必要な情報要素の抽出 */
        switch (ie_type) {
            case IAX_IE_CALLED_NUMBER:
                if (ie_length < sizeof(info->called_number)) {
                    memcpy(info->called_number, &data[pos], ie_length);
                    info->called_number[ie_length] = '\0';
                }
                break;
            
            case IAX_IE_CALLING_NUMBER:
                if (ie_length < sizeof(info->calling_number)) {
                    memcpy(info->calling_number, &data[pos], ie_length);
                    info->calling_number[ie_length] = '\0';
                }
                break;
                
            case IAX_IE_CALLING_NAME:
                if (ie_length < sizeof(info->calling_name)) {
                    memcpy(info->calling_name, &data[pos], ie_length);
                    info->calling_name[ie_length] = '\0';
                }
                break;
                
            default:
                /* その他の情報要素はスキップ */
                break;
        }
        
        pos += ie_length;
    }
}

/* 着信呼び出しを検出 */
int detect_incoming_call(const unsigned char *packet, int packet_len, iax_call_info_t *call_info) {
    iax_full_header_t header;
    
    /* パケット長のチェック - Full Frame ヘッダーの最低長は12バイト */
    if (packet_len < 12) {
        return 0;
    }
    
    /* ヘッダーの解析 */
    parse_iax_full_header(packet, &header);
    
    /* Full Frameでなければ無視 */
    if (header.f_bit != 1) {
        return 0;
    }
    
    /* 着信検出: NEW メッセージまたは RINGING メッセージか */
    int is_incoming_call = 0;
    
    if (header.frametype == IAX_FRAMETYPE_IAX && header.subclass == IAX_SUBCLASS_NEW) {
        /* NEW メッセージ（新規着信） */
        is_incoming_call = 1;
        LOG_MESSAGE("Detected NEW call");
        
        /* 情報要素の解析 */
        parse_information_elements(packet + 12, packet_len - 12, call_info);
        
    } else if (header.frametype == IAX_FRAMETYPE_CONTROL && header.subclass == IAX_SUBCLASS_RINGING) {
        /* RINGING メッセージ（呼出中） */
        is_incoming_call = 2;
        LOG_MESSAGE("Detected RINGING");
    }
    
    return is_incoming_call;
}


#define SOURCE_FILE "~/.udp_repeater_source"

int is_server_mode = 0;
uint32_t packet_sno = 0; // シリアル番号を初期化
uint64_t current_time = 0; // UNIX時刻を初期化

uint32_t rpacket_index_top = (uint32_t)-1; // インデックスtopを初期化
uint32_t rpacket_index_bottom = (uint32_t)-1; // インデックスbottomを初期化
uint32_t requesting = 0; // request_idを初期化
uint32_t requested = (uint32_t)-1; // requestedを初期化

#define PACKET_SIZE 2048
#define BUFFERED_PACKET_SIZE (PACKET_SIZE - sizeof(uint16_t)) // パケットサイズ
struct __attribute__((packed)) Packet {
    uint16_t packet_len; // パケットサイズ
    char data[PACKET_SIZE]; // パケットデータ
};

#define PACKET_POOL_SIZE 1024 // バッファサイズ

struct __attribute__((packed)) BufferedPacket {
    uint16_t packet_len; // パケットサイズ
    char data[BUFFERED_PACKET_SIZE]; // パケットデータ
} bufferedPackets[PACKET_POOL_SIZE]; // PACKET_POOL_SIZE個収容可能なバッファ
#define bufferedPacketPtr(index) (&bufferedPackets[(index) % PACKET_POOL_SIZE]) // bufferedPacketのポインタを取得するマクロ

#define UNARRIVED_MAX 256 // 到着していないパケット番号を格納する配列のサイズ

struct __attribute__((packed)) UnarrivedInfoPacket {
    uint16_t packet_len; // パケットサイズ
    uint64_t time; // 時刻
    uint64_t program_start_time; // プロセス開始時刻
    uint32_t program_pid; // プロセスID
    uint32_t sno; // = -1; シリアル番号
    uint32_t request; // 要求id
    uint32_t unarrived[UNARRIVED_MAX]; // 到着していないパケット番号を格納する配列
};


#define TAGGED_DATA_SIZE (PACKET_SIZE - sizeof(uint64_t) * 2 - sizeof(uint32_t) * 2)
struct __attribute__((packed)) TaggedPacket {
    uint16_t packet_len; // パケットサイズ
    uint64_t time; // 時刻
    uint64_t program_start_time; // プロセス開始時刻
    uint32_t program_pid; // プロセスID
    uint32_t sno; // = -1; シリアル番号
    char data[TAGGED_DATA_SIZE]; // 到着していないパケット番号を格納する配列
} taggedPackets[PACKET_POOL_SIZE]; // PACKET_POOL_SIZE個収容可能なバッファ
#define taggedPacketPtr(index) ((struct TaggedPacket*)&(taggedPackets[(index) % PACKET_POOL_SIZE])) // bufferedPacketのポインタを取得するマクロ

#define TAG_SIZE ((uint64_t)&((struct TaggedPacket*)0)->data - (uint64_t)&((struct Packet*)0)->data) // タグのサイズ

void add_timestamp_and_sno(struct Packet* packet) {
    uint64_t timestamp_network_order = htobe64(current_time); // ネットワークバイトオーダーに変換
    uint32_t sno_network_order = htonl(packet_sno); // ネットワイトオーダーに変換

    LOG_MESSAGE("add_timestamp_and_sno: packet_sno = %d", packet_sno);
    struct TaggedPacket *tp = taggedPacketPtr(packet_sno);
    LOG_MESSAGE("add_timestamp_and_sno: tp = %lx", tp);
    tp->packet_len = packet->packet_len + TAG_SIZE; // 受信したパケットのサイズにタグのサイズを加えて格納
    tp->program_start_time = htobe64(program_start_time); // プロセス開始時刻を格納
    tp->program_pid = htonl((uint32_t)program_pid); // プロセスIDを格納
    tp->time = timestamp_network_order; // ネットワークバイトオーダーのUNIX時刻を格納
    tp->sno = sno_network_order; // ネットワイトオーダーのシリアル番号を格納
    LOG_MESSAGE("add_timestamp_and_sno: tp->sno = %d, tp->time = %ld, tp->packet_len = %d", ntohl(tp->sno), be64toh(tp->time), tp->packet_len);
    memcpy(tp->data, packet->data, packet->packet_len); // 受信したパケットのデータを格納
    LOG_MESSAGE("add_timestamp_and_sno: md5_6(tp->data)= %s", md5_6(tp->data, tp->packet_len - TAG_SIZE));
    (packet_sno)++; // シリアル番号をインクリメント
}



int recvFrom(struct Packet* packet, int sock, struct sockaddr_in* client_addr, socklen_t *addr_len) {
    LOG_MESSAGE("recvFrom: sock = %d", sock);
    ssize_t recv_len = recvfrom(sock, (char*)&packet->data, PACKET_SIZE, 0,
                                (struct sockaddr *)client_addr, addr_len);
    LOG_MESSAGE("recvFrom: %d bytes, client_addr = %lx", (int)recv_len, client_addr);
    if(client_addr)
        LOG_MESSAGE("recvFrom: %d bytes from %s:%d",
            (int)recv_len, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    packet->packet_len = recv_len; // 受信したパケットのサイズを格納
    return (int)recv_len; // 受信したパケットのサイズを返す
}

#define isUnarrived(index) (bufferedPacketPtr(index)->packet_len == 0 || (uint16_t)-16 < bufferedPacketPtr(index)->packet_len) // 到着していないパケットか再送有給が上限に達したパケットを判定するマクロ
#define isUnarrivedMax(index) (bufferedPacketPtr(index)->packet_len == (uint16_t)-16) // 到着していないパケットを判定するマクロ
#define incUnarrived(index) (--bufferedPacketPtr(index)->packet_len) // 到着していないパケットを判定するマクロ

// パケットの先頭64ビットをUNIX時刻として解釈し、判定する関数
// 60秒以上ずれていない場合は、先頭のUNIX時刻と32ビットシリアル番号を削除
int validate_and_strip_packet(struct TaggedPacket* packet, size_t *pktCount, struct UnarrivedInfoPacket *unrarrivedInfoPacket) {
    uint16_t len = packet->packet_len; // パケットサイズを取得
    if (len < TAG_SIZE) {
        LOG_MESSAGE("Dropped packet: too small to contain a valid tag.");
        return 0; // 無効なパケット
    }

    uint64_t time_stamp = be64toh(packet->time); // ネットワークバイトオーダーをホストバイトオーダーに変換

    // 現在の時刻と比較
    if (llabs((int64_t)(time_stamp - current_time)) > 120) {
        LOG_MESSAGE("Dropped packet: timestamp %lu is out of sync with current time %lu.",
            time_stamp, current_time);
        return 0; // 無効なパケット
    }

    uint64_t _program_start_time = be64toh(packet->program_start_time); // ネットワークバイトオーダーをホストバイトオーダーに変換
    uint16_t peer_program_renewed = 0; // 相手側プロセスが更新されたかどうかを示すフラグ
    if (peer_program_start_time == 0 || peer_program_start_time < _program_start_time) {
        peer_program_start_time = _program_start_time; // 相手側プロセス開始時刻を更新
        peer_program_pid = ntohl(packet->program_pid); // 相手側プロセスIDを更新
        peer_program_renewed = 1; // 相手側プロセスが更新された
    }else if(peer_program_start_time > _program_start_time) { // 相手側プロセス開始時刻が古い場合
        LOG_MESSAGE("Dropped packet: emitted by old program.");
        return 0; // 無効なパケット
    }else if(peer_program_pid != ntohl(packet->program_pid)) { //プロセスIDだけ変更された場合
        peer_program_pid = ntohl(packet->program_pid); // プロセスIDを更新
        peer_program_renewed = 1; // 相手側プロセスが更新された
    }

    // 32ビットのシリアル番号を取得
    uint32_t p_sno = ntohl(packet->sno); // ネットワークバイトオーダーをホストバイトオーダーに変換

    if(p_sno == (uint32_t)-1) {
        return -1; // ユーティリティパケット
    }
    // rpacket_index_bottomの更新
    if (rpacket_index_bottom == (uint32_t)-1) {
        rpacket_index_bottom = p_sno;
    }

    // rpacket_index_topの更新
    if (rpacket_index_top == (uint32_t)-1) {
        rpacket_index_top = p_sno + 1;
    }else if (peer_program_renewed || (rpacket_index_top > PACKET_POOL_SIZE && p_sno < rpacket_index_top - PACKET_POOL_SIZE) || rpacket_index_top + PACKET_POOL_SIZE < p_sno) {
        // rpacket_index_topがPACKET_POOL_SIZE以上で、snoがrpacket_index_top-PACKET_POOL_SIZEより小さい場合、またはrpacket_index_top+PACKET_POOL_SIZEより大きい場合
        // rpacket_index_topをsnoに更新
        rpacket_index_top = p_sno + 1;
        rpacket_index_bottom = p_sno;
        requested = (uint32_t)-1; // request_id_topを初期化
    }else if (rpacket_index_top <= p_sno) { //新しいパケット
        // rpacket_index_topからsno-1までの範囲（まだ到着していない）をゼロクリア
        for (; rpacket_index_top < p_sno - 1; ++rpacket_index_top) 
            bufferedPacketPtr(rpacket_index_top)->packet_len = 0; // 先頭2バイトをゼロクリア
        rpacket_index_top = p_sno + 1;
        if(rpacket_index_top > rpacket_index_bottom + PACKET_POOL_SIZE - 1)
            rpacket_index_bottom = rpacket_index_top - PACKET_POOL_SIZE - 1; // rpacket_index_bottomを更新
    }else if(bufferedPacketPtr(p_sno)->packet_len > 0 && bufferedPacketPtr(p_sno)->packet_len < (uint16_t)-16) {
        LOG_MESSAGE("validate_and_strip_packet: packet sno %d already arrived.", p_sno);
        return 0; // 無効なパケット。既にデータが到着している。
    }

    // パケットのサイズ（UNIX時刻とシリアル番号を除いたサイズ）を計算
    uint16_t payload_size = len - TAG_SIZE;
    LOG_MESSAGE("validate_and_strip_packet: packet_len = %d, payload_size = %d\n, md5 = %s", len, payload_size, md5_6(packet->data, payload_size));

    // rpacketにサイズと内容を格納
    bufferedPacketPtr(p_sno)->packet_len = payload_size; // 先頭2バイトにサイズを格納
    memcpy(bufferedPacketPtr(p_sno)->data, packet->data, payload_size); // 内容を格納

    //--------連続したパケットをpbufferとpktCountで指定する---------------
    uint32_t i = rpacket_index_bottom, j = 0;
    for(; i < rpacket_index_top; ++i)
        if (isUnarrived(i)){
            // パケットが到着していない場合で、再送要求が上限に達していない場合
            if(j < 250){ //最大限送信可能
                incUnarrived(i);
                LOG_MESSAGE("validate_and_strip_packet: insert %d to request unarrived packet.", i);
                unrarrivedInfoPacket->unarrived[j++] = htonl(i); // 到着していないパケット番号を格納
            }
            break;
        }
    *pktCount = i - rpacket_index_bottom; // 先頭から連続して受信済みパケットの数を返す
    rpacket_index_bottom += *pktCount; // 受信済みパケットの範囲を更新
    for(; i < rpacket_index_top; ++i)
        if (isUnarrived(i)){
            // パケットが到着していない場合
            if(j < 250){ //最大限送信可能
                incUnarrived(i);
                LOG_MESSAGE("validate_and_strip_packet: insert %d to request unarrived packet.", i);
                unrarrivedInfoPacket->unarrived[j++] = htonl(i); // 到着していないパケット番号を格納
            }
        }
    if(j > 0){
        unrarrivedInfoPacket->request = requesting++; // request_idを格納
        unrarrivedInfoPacket->unarrived[j++] = htonl((uint32_t)-1); // 到着していないパケット番号の終端を示す
        unrarrivedInfoPacket->packet_len = (uint64_t)&((struct UnarrivedInfoPacket*)0)->unarrived + sizeof(uint32_t) * j; // パケットサイズを計算
        unrarrivedInfoPacket->sno = htonl(-1); // ネットワークバイトオーダーで-1を格納
        unrarrivedInfoPacket->time = htobe64(current_time); // ネットワイトオーダーのUNIX時刻を格納
        unrarrivedInfoPacket->program_start_time = htobe64(program_start_time); // プロセス開始時刻を格納
        unrarrivedInfoPacket->program_pid = htonl((uint32_t)program_pid); // プロセスIDを格納
    }else{
        unrarrivedInfoPacket->packet_len = 0; // パケットサイズを計算
    }
    //--------穴の空いたパケット番号をユーティリティパケットに格納して返送する--------


    return 1; // 有効なパケット
}

int fr, fw; // パイプの読み取り用と書き込み用

// 別スレッドで10秒ごとにfwに'\0'を書き込む関数
void *timer_thread(void *arg) {
    while (1) {
        sleep(10); // 10秒待機
        char dummy = '\0';
        write(fw, &dummy, 1); // fwに1バイト書き込む
    }
    return NULL;
}

int sendCount = 5; // パケットを送信する回数

void send_packet(int count, int sock, struct sockaddr_in* addr, struct Packet* packet) {
    //print_sockaddr((struct sockaddr *)addr); // 送信先アドレスを表示
    for(int i = 0; i < count; ++i) {
        LOG_MESSAGE("send_packet: packet->packet_len = %d", packet->packet_len);
        ssize_t sent_len = sendto(sock, packet->data, packet->packet_len, 0,
                                (struct sockaddr *)addr, sizeof(*addr));
        if (sent_len < 0)
            LOG_MESSAGE("Error sending packet: %s", strerror(errno));
    }
}


uint32_t fuka = 0;

void trans_packet(int to_inner, int sock, struct sockaddr_in* addr, struct Packet* packet, int peer_sock, struct sockaddr_in* peer_addr) {
    size_t pktCount, itemCount;
    struct UnarrivedInfoPacket* requestPacket;
    struct UnarrivedInfoPacket unarrivedInfoPacket;
    if (to_inner) {
        // パケットを検証して先頭のUNIX時刻とシリアル番号を削除。パケットバッファに格納して、連続している受信済パケットの範囲をpbufferとpktCountに返す
        switch (validate_and_strip_packet((struct TaggedPacket *)packet, &pktCount, &unarrivedInfoPacket)) {
        case 0:
            return; // 無効なパケットを破棄
        case -1:
            // 未着再送信要求の場合
            // 処理をする
            requestPacket = (struct UnarrivedInfoPacket *)packet;
            itemCount = (requestPacket->packet_len - (uint32_t)(uint64_t)&((struct UnarrivedInfoPacket *)NULL)->unarrived) / sizeof(uint32_t);
            LOG_MESSAGE("received resend request of unarrived packets, request ID = %d, itemCount = %u.", requestPacket->request, itemCount);
            if(requested == (uint32_t)-1 || requested < requestPacket->request){ // 新しいrequestのみ処理
                requested = requestPacket->request;
                uint32_t i;
                for(uint32_t j = 0; j < itemCount ; ++j){
                    memcpy(&i, &requestPacket->unarrived[j], sizeof(i));
                    i = ntohl(i); // ネットワークバイトオーダーをホストバイトオーダーに変換
                    if(i == (uint32_t)-1) 
                        break; // 到着していないパケット番号の終端を示す
                    if ((packet_sno > PACKET_POOL_SIZE && i < packet_sno - PACKET_POOL_SIZE) || packet_sno <= i) {
                        // 到着していないパケット番号が範囲外の場合
                        LOG_MESSAGE("Invalid unarrived packet number: %u", i);
                        continue;
                    }
                    // 到着していないパケットを再送する
                    LOG_MESSAGE("resend unarrived packet, %d to peer", i);
                    send_packet(sendCount, peer_sock, peer_addr, (struct Packet*)taggedPacketPtr(i));
                }
            }
            return;
        }
        LOG_MESSAGE("Received valid packet from outside, sno = %d, sending to inner...", ntohl(((struct TaggedPacket *)packet)->sno));
        LOG_MESSAGE("addr->sin_port = %d", addr->sin_port);
        LOG_MESSAGE("transferrable packet count = %d", pktCount);
        LOG_MESSAGE("rpacket_index_bottom = %d", rpacket_index_bottom);
        if (addr->sin_port != 0)
            for (size_t i = rpacket_index_bottom - pktCount; i < rpacket_index_bottom; ++i)
                // 転送先にパケットを送信
                if(!isUnarrivedMax(i)){ // 再送要求限度を超えても到着していないパケット番号をスキップ
                    LOG_MESSAGE("send_packet, %d to forward destination", i);
                    send_packet(1, sock, addr, (struct Packet*)bufferedPacketPtr(i));
                }
        if (unarrivedInfoPacket.packet_len > 0) {
            // 到着していないパケット番号を返送
            itemCount = (unarrivedInfoPacket.packet_len - (uint32_t)(uint64_t)&((struct UnarrivedInfoPacket *)NULL)->unarrived) / sizeof(uint32_t);
            LOG_MESSAGE("send_packet to peer : request of unarrived %u packets", itemCount);
            send_packet(sendCount, peer_sock, peer_addr, (struct Packet*)&unarrivedInfoPacket);
        }
    }else{
        // パケットサイズとUNIX時刻とシリアル番号を付加する
        // packet_snoをインクリメント
        add_timestamp_and_sno(packet);
        pktCount = 1;
        LOG_MESSAGE("send_packet, %u with timestamp = %ld and sno = %d, size = %d, md5 = %s", 
            packet_sno - 1, 
            be64toh(taggedPacketPtr(packet_sno - 1)->time), 
            ntohl(taggedPacketPtr(packet_sno - 1)->sno), 
            taggedPacketPtr(packet_sno - 1)->packet_len,
            md5_6(taggedPacketPtr(packet_sno - 1)->data, taggedPacketPtr(packet_sno - 1)->packet_len - TAG_SIZE) // MD5ハッシュを計算
        );
        //if(fuka % 2 != 0){ // 負荷をかける。故意にパケットを落とす。
            send_packet(sendCount, sock, addr, (struct Packet*)taggedPacketPtr(packet_sno - 1)); // taggedPacketsのポインタを取得
        //}
        fuka++;
    }

}

uint64_t last_call_time = 0;


int main(int argc, char *argv[]) {
    program_invocation_short_name = basename(argv[0]);
    program_pid = getpid();
    program_start_time = get_process_start_time(program_pid);

    // コマンドライン引数を解析
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0) {
            is_server_mode = 1;
            break;
        }
    }

    if (argc < 6 || (is_server_mode && argc != 7)) {
        fprintf(stderr, "Usage: %s --server <repeat_count> <listen_port> <bind_port> <forward_host> <forward_port>\n", argv[0]);
        fprintf(stderr, "       %s          <repeat_count> <listen_port> <bind_port> <forward_host> <forward_port> <url_on_calling>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // コマンドライン引数から設定を取得
    sendCount = atoi(argv[is_server_mode ? 2 : 1]);
    int listen_port = atoi(argv[is_server_mode ? 3 : 2]);
    int bind_port = atoi(argv[is_server_mode ? 4 : 3]);
    const char *forward_host = argv[is_server_mode ? 5 : 4];
    int forward_port = atoi(argv[is_server_mode ? 6 : 5]);

    char* url = NULL; // URLを初期化
    char url_hostname[256];
    char url_path[256];
    uint16_t url_port;
    if(!is_server_mode && argc >= 6){
        url = argv[6]; // URLを取得
        if (parse_url(url, url_hostname, url_path, &url_port) < 0) {
            fprintf(stderr, "Failed to parse URL: %s\n", url);
            exit(EXIT_FAILURE);
        }
    }
        
    if (sendCount <= 0 || listen_port <= 0 || bind_port <= 0 || forward_port <= 0) {
        LOG_AND_EXIT("Error: Repeat count and Ports must be positive integers.");
    }

    // tを現在時刻で初期化
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    current_time = (uint64_t)ts.tv_sec;
    LOG_MESSAGE("Initialized current_time: %lu", current_time);

    char resolved_source_path[256];
    resolve_path(SOURCE_FILE, resolved_source_path, sizeof(resolved_source_path));

    // パイプを作成
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        LOG_AND_EXIT("Error creating pipe: %s", strerror(errno));
    }
    fr = pipe_fds[0]; // 読み取り用
    fw = pipe_fds[1]; // 書き込み用

    // 別スレッドを作成
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, timer_thread, NULL) != 0) {
        LOG_AND_EXIT("Error creating thread: %s", strerror(errno));
    }

    int listen_sock, forward_sock;
    struct sockaddr_in listen_addr, forward_addr, client_addr, saved_client_addr;
    socklen_t addr_len = sizeof(client_addr);
    fd_set read_fds;
    int max_fd;

    // 保存された送信元情報を初期化
    memset(&saved_client_addr, 0, sizeof(saved_client_addr));

    // 保存された送信元情報をファイルから読み込む
    FILE *file = fopen(resolved_source_path, "r");
    printf("Loading source from %s\n", resolved_source_path);
    LOG_MESSAGE("Loading source from %s", resolved_source_path);
    if (file) {
        char ip[INET_ADDRSTRLEN];
        int port;
        if (fscanf(file, "%s %d", ip, &port) == 2) {
            saved_client_addr.sin_family = AF_INET;
            saved_client_addr.sin_addr.s_addr = inet_addr(ip);
            saved_client_addr.sin_port = htons(port);
            puts(ip);
            LOG_MESSAGE("Loaded source: %s:%d", ip, port);
        }
        fclose(file);
    }

    // 待ち受け用ソケットの作成
    if ((listen_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG_AND_EXIT("Error creating listen socket: %s", strerror(errno));
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        LOG_AND_EXIT("Error binding listen socket: %s", strerror(errno));
    }

    // 転送用ソケットの作成
    if ((forward_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG_AND_EXIT("Error creating forward socket: %s", strerror(errno));
    }

    // サーバー名をIPv4アドレスに解決
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP

    char port_str[12];
    snprintf(port_str, sizeof(port_str), "%d", forward_port);

    if (getaddrinfo(forward_host, port_str, &hints, &res) != 0) {
        LOG_AND_EXIT("Error resolving forward address: %s", strerror(errno));
    }

    // 転送先アドレスを設定
    memcpy(&forward_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(bind_port);

    if (bind(forward_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_AND_EXIT("Error binding forward socket: %s", strerror(errno));
    }

    LOG_MESSAGE("Listening on port %d and forwarding to %s:%d", listen_port, forward_host, forward_port);


    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        FD_SET(forward_sock, &read_fds);
        FD_SET(fr, &read_fds); // パイプの読み取り用ファイルディスクリプタを監視
        max_fd = (listen_sock > forward_sock) ? listen_sock : forward_sock;
        max_fd = (max_fd > fr) ? max_fd : fr;

        // selectでソケットとパイプを監視
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            LOG_MESSAGE("Error in select: %s", strerror(errno));
            break;
        }

        if (FD_ISSET(fr, &read_fds)) {
            // パイプが読み込み可能になった場合
            char dummy;
            read(fr, &dummy, 1); // 1バイト読み込んで捨てる

            // 現在のUNIX時刻を取得してtに格納
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            current_time = (uint64_t)ts.tv_sec;
            LOG_MESSAGE("Updated current_time: %lu", current_time);
        }

        struct Packet packet;
        if (FD_ISSET(listen_sock, &read_fds)) {
            // 待ち受けソケットからパケットを受信
            LOG_MESSAGE("listen_sock is ready to read");
            if (recvFrom(&packet, listen_sock, &client_addr, &addr_len) < 0) {
                LOG_MESSAGE("Error receiving packet on listen socket: %s", strerror(errno));
                continue;
            }

            if(!is_server_mode)
                LOG_MESSAGE("Received packet from %s:%d, forwarding...",
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            else
                LOG_MESSAGE("Received packet, id = %d from %s:%d, forwarding...",
                    ntohl(((struct TaggedPacket *)&packet)->sno),
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

            // 送信元情報を保存
            if (memcmp(&saved_client_addr, &client_addr, sizeof(client_addr)) != 0) {
                saved_client_addr = client_addr;
                file = fopen(resolved_source_path, "w");
                if (file) {
                    fprintf(file, "%s %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    fclose(file);
                }
            }

            trans_packet(is_server_mode, forward_sock, &forward_addr, &packet, listen_sock, &client_addr);

        }

        if (FD_ISSET(forward_sock, &read_fds)) {
            // 転送用ソケットからパケットを受信
            LOG_MESSAGE("forward_sock is ready to read");
            if (recvFrom(&packet, forward_sock, NULL, NULL) < 0){
                LOG_MESSAGE("Error receiving packet on forward socket: %s", strerror(errno));
                continue;
            }
            LOG_MESSAGE("trans_packet");
            trans_packet(!is_server_mode, listen_sock, &saved_client_addr, &packet, forward_sock, &forward_addr);
            if(!is_server_mode && url){
                /* パケット内容の解析と着信検出 */
                iax_call_info_t call_info;
                int call_status = detect_incoming_call(packet.data, packet.packet_len, &call_info);

                /* 着信が検出された場合はurlをGET */
                if (call_status == 1) { // NEW メッセージ
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    uint64_t current_time = (uint64_t)ts.tv_sec;
            
                    // 前回の着信検出から3秒以内の場合はスキップ
                    if (current_time - last_call_time < 3) {
                        LOG_MESSAGE("Skipping get_url: Last call detected %lu seconds ago.", current_time - last_call_time);
                        continue;
                    }
            
                    // 前回の着信検出時刻を更新
                    last_call_time = current_time;
            
                    // URL情報をスレッドに渡すために構造体を作成
                    UrlInfo *url_info = malloc(sizeof(UrlInfo));
                    if (!url_info) {
                        LOG_MESSAGE("Error allocating memory for URL info: %s", strerror(errno));
                        continue;
                    }

                    strncpy(url_info->hostname, url_hostname, sizeof(url_info->hostname) - 1);
                    url_info->hostname[sizeof(url_info->hostname) - 1] = '\0';
                    strncpy(url_info->path, url_path, sizeof(url_info->path) - 1);
                    url_info->path[sizeof(url_info->path) - 1] = '\0';
                    url_info->port = url_port;

                    // スレッドを作成してget_urlを実行
                    pthread_t thread_id;
                    if (pthread_create(&thread_id, NULL, get_url_thread, url_info) != 0) {
                        LOG_MESSAGE("Error creating thread for get_url: %s", strerror(errno));
                        free(url_info); // スレッド作成に失敗した場合はメモリを解放
                    } else {
                        pthread_detach(thread_id); // スレッドをデタッチ
                    }
                }
            }
        }
    }

    close(listen_sock);
    close(forward_sock);
    close(fr);
    close(fw);
    return 0;
}

