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

// グローバル変数
FILE *log_file = NULL;
const char* program_invocation_short_name = NULL;

// ログ出力用関数
void log_message(const char *format, ...) {
    if (!log_file) return;

    struct timeval tv;
    gettimeofday(&tv, NULL);

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
    va_list args;
    va_start(args, format);
    fprintf(log_file, "[%s.%03ld] [%s:%d] ", time_buffer, milliseconds, process_name, pid);
    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");
    va_end(args);

    fflush(log_file); // ログを即時書き込み
}

void log_and_exit(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_message(format, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

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
        log_message("Error: HTTPS is not supported in this implementation.");
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
        log_message("Error resolving hostname: %s", strerror(errno));
        return;
    }

    // IPv4を優先してアドレスを選択
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
            sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sock < 0) {
                log_message("Error creating socket: %s", strerror(errno));
                continue; // 次のアドレスを試す
            }

            // サーバーに接続
            if (connect(sock, rp->ai_addr, rp->ai_addrlen) < 0) {
                log_message("Error connecting to server: %s", strerror(errno));
                close(sock); // 接続失敗時はソケットを閉じる
                continue;
            }

            break; // 接続成功
        }
    }

    if (rp == NULL) {
        log_message("Error: get_url: Could not connect to any address for %s", hostname);
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
        log_message("Error sending request: %s", strerror(errno));
        close(sock);
        return;
    }

    // レスポンスを受信
    printf("Response:\n");
    ssize_t bytes_received;
    while ((bytes_received = recv(sock, response, sizeof(response) - 1, 0)) > 0) {
        response[bytes_received] = '\0'; // NULL終端
        printf("%s", response);         // レスポンスを出力
    }

    // レスポンス受信時のエラー
    if (bytes_received < 0) {
        log_message("Error receiving response: %s", strerror(errno));
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
            printf("Warning: IE length exceeds packet bounds\n");
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
        printf("Detected NEW call\n");
        
        /* 情報要素の解析 */
        parse_information_elements(packet + 12, packet_len - 12, call_info);
        
    } else if (header.frametype == IAX_FRAMETYPE_CONTROL && header.subclass == IAX_SUBCLASS_RINGING) {
        /* RINGING メッセージ（呼出中） */
        is_incoming_call = 2;
        printf("Detected RINGING\n");
    }
    
    return is_incoming_call;
}


#define SOURCE_FILE "~/.udp_repeater_source"

int is_server_mode = 0;
uint32_t packet_sno = 0; // シリアル番号を初期化
uint64_t current_time = 0; // UNIX時刻を初期化

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

struct __attribute__((packed)) BufferedPacket {
    uint16_t packet_len; // パケットサイズ
    char data[BUFFERED_PACKET_SIZE]; // パケットデータ
} bufferedPackets[1024]; // 1024個収容可能なバッファ
#define bufferedPacketPtr(index) (&bufferedPackets[(index) % 1024]) // bufferedPacketのポインタを取得するマクロ

#define UNARRIVED_MAX 1024 // 到着していないパケット番号を格納する配列のサイズ

struct __attribute__((packed)) UnarrivedInfoPacket {
    uint16_t packet_len; // パケットサイズ
    uint64_t time; // 時刻
    uint32_t sno; // = -1; シリアル番号
    uint32_t request; // 要求id
    uint32_t unarrived[UNARRIVED_MAX]; // 到着していないパケット番号を格納する配列
}; // PACKET_SIZEバイトのパケットを1024個収容可能なバッファ


#define TAGGED_DATA_SIZE (PACKET_SIZE - sizeof(uint64_t) - sizeof(uint32_t))
struct __attribute__((packed)) TaggedPacket {
    uint16_t packet_len; // パケットサイズ
    uint64_t time; // 時刻
    uint32_t sno; // = -1; シリアル番号
    char data[TAGGED_DATA_SIZE]; // 到着していないパケット番号を格納する配列
} taggedPackets[1024]; // 1024個収容可能なバッファ
#define taggedPacketPtr(index) (&taggedPackets[(index) % 1024]) // bufferedPacketのポインタを取得するマクロ

void add_timestamp_and_sno(struct Packet* packet) {
    uint64_t timestamp_network_order = htobe64(current_time); // ネットワークバイトオーダーに変換
    uint32_t sno_network_order = htonl(packet_sno); // ネットワイトオーダーに変換

    struct TaggedPacket *tp = taggedPacketPtr(packet_sno);
    tp->packet_len = packet->packet_len + sizeof(uint64_t) + sizeof(uint32_t); // 受信したパケットのサイズにタグのサイズを加えて格納
    tp->time = timestamp_network_order; // ネットワークバイトオーダーのUNIX時刻を格納
    tp->sno = sno_network_order; // ネットワイトオーダーのシリアル番号を格納
    memcpy(tp->data, packet->data, packet->packet_len); // 受信したパケットのデータを格納
    (packet_sno)++; // シリアル番号をインクリメント
}



int recvFrom(struct Packet* packet, int sock, struct sockaddr_in* client_addr, socklen_t *addr_len) {
    ssize_t recv_len = recvfrom(sock, (char*)&packet->data, PACKET_SIZE, 0,
                                (struct sockaddr *)client_addr, addr_len);
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
    if (len < sizeof(uint64_t) + sizeof(uint32_t)) {
        printf("Dropped packet: too small to contain a valid timestamp and sno.\n");
        return 0; // 無効なパケット
    }

    uint64_t time_stamp = be64toh(packet->time); // ネットワークバイトオーダーをホストバイトオーダーに変換

    // 現在の時刻と比較
    if (llabs((int64_t)(time_stamp - current_time)) > 120) {
        printf("Dropped packet: timestamp %lu is out of sync with current time %lu.\n",
            time_stamp, current_time);
        return 0; // 無効なパケット
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
        rpacket_index_top = p_sno;
    }else if ((rpacket_index_top > 1024 && p_sno < rpacket_index_top - 1024) || rpacket_index_top + 1024 < p_sno) {
        // rpacket_index_topが1024以上で、snoがrpacket_index_top-1024より小さい場合、またはrpacket_index_top+1024より大きい場合
        // rpacket_index_topをsnoに更新
        rpacket_index_top = p_sno + 1;
        rpacket_index_bottom = p_sno;
        requested = (uint32_t)-1; // request_id_topを初期化
    }else if (rpacket_index_top <= p_sno) { //新しいパケット
        // rpacket_index_topからsno-1までの範囲（まだ到着していない）をゼロクリア
        for (; rpacket_index_top < p_sno - 1; ++rpacket_index_top) 
            bufferedPacketPtr(rpacket_index_top)->packet_len = 0; // 先頭2バイトをゼロクリア
        rpacket_index_top = p_sno + 1;
    }else if(bufferedPacketPtr(p_sno)->packet_len != 0) {
        return 0; // 無効なパケット。既にデータが到着している。
    }

    // パケットのサイズ（UNIX時刻とシリアル番号を除いたサイズ）を計算
    uint16_t payload_size = len - (sizeof(uint64_t) + sizeof(uint32_t));

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
                unrarrivedInfoPacket->unarrived[j++] = i; // 到着していないパケット番号を格納
            }
            break;
        }
    *pktCount = i - rpacket_index_bottom; // 先頭から連続して受信済みパケットの数を返す
    for(; i < rpacket_index_top; ++i)
        if (isUnarrived(i)){
            // パケットが到着していない場合
            if(j < 250){ //最大限送信可能
                incUnarrived(i);
                unrarrivedInfoPacket->unarrived[j++] = i; // 到着していないパケット番号を格納
            }
            break;
        }
    if(j > 0){
        unrarrivedInfoPacket->request = requesting++; // request_idを格納
        unrarrivedInfoPacket->unarrived[j++] = (u_int32_t)-1; // 到着していないパケット番号の終端を示す
        unrarrivedInfoPacket->packet_len = sizeof(uint64_t) + sizeof(uint32_t) + j * sizeof(uint32_t); // パケットサイズを計算
        unrarrivedInfoPacket->sno = htonl(-1); // ネットワークバイトオーダーで-1を格納
        unrarrivedInfoPacket->time = htobe64(current_time); // ネットワイトオーダーのUNIX時刻を格納
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
    for(int i = 0; i < count; ++i) {
        ssize_t sent_len = sendto(sock, packet->data, packet->packet_len, 0,
                                (struct sockaddr *)addr, sizeof(*addr));
        if (sent_len < 0) {
            log_message("Error sending packet: %s", strerror(errno));
        } else {
            log_message("Sent packet with timestamp %lu and sno %u to forward destination.\n", current_time, packet_sno - 1);
        }
    }
}


void trans_packet(int to_inner, int sock, struct sockaddr_in* addr, struct Packet* packet, int peer_sock, struct sockaddr_in* peer_addr) {
    size_t pktCount;
    struct UnarrivedInfoPacket unrarrivedInfoPacket;
    if (to_inner) {
        // パケットを検証して先頭のUNIX時刻とシリアル番号を削除。パケットバッファに格納して、連続している受信済パケットの範囲をpbufferとpktCountに返す
        switch (validate_and_strip_packet((struct TaggedPacket *)packet, &pktCount, &unrarrivedInfoPacket)) {
        case 0:
            return; // 無効なパケットを破棄
        case -1:
            // 未着再送信要求の場合
            // 処理をする
            struct UnarrivedInfoPacket* requestPacket = (struct UnarrivedInfoPacket *)packet;
            if(requested == (uint32_t)-1 || requested < requestPacket->request){ // 新しいrequestのみ処理
                requested = requestPacket->request;
                uint32_t i;
                for(uint32_t j = 0; j < UNARRIVED_MAX ; ++j){
                    memcpy(&i, &requestPacket->unarrived[j], sizeof(i));
                    if(i == (uint32_t)-1) 
                        break; // 到着していないパケット番号の終端を示す
                    if (i < packet_sno - 1024 || packet_sno <= i) {
                        // 到着していないパケット番号が範囲外の場合
                        log_message("Invalid unarrived packet number: %u\n", i);
                        continue;
                    }
                    // 到着していないパケットを再送する
                    send_packet(sendCount, peer_sock, peer_addr, (struct Packet*)taggedPacketPtr(i));
                }
                return;
            }
        }
        printf("Received valid packet from forward destination, sending back to source...\n");
        if (addr->sin_port != 0)
            for (size_t i = rpacket_index_bottom; i < rpacket_index_bottom + pktCount; ++i){
                // 転送先にパケットを送信
                if(!isUnarrivedMax(i)) // 再送要求限度を超えても到着していないパケット番号をスキップ
                    send_packet(1, sock, addr, (struct Packet*)bufferedPacketPtr(i));
            }
        if (unrarrivedInfoPacket.packet_len > 0) {
            // 到着していないパケット番号を返送
            send_packet(sendCount, peer_sock, peer_addr, (struct Packet*)&unrarrivedInfoPacket);
        }
    }else{
        // パケットサイズとUNIX時刻とシリアル番号を付加する
        // packet_snoをインクリメント
        add_timestamp_and_sno(packet);
        pktCount = 1;
        send_packet(sendCount, sock, addr, (struct Packet*)taggedPacketPtr(packet_sno - 1)); // taggedPacketsのポインタを取得
    }

}

uint64_t last_call_time = 0;


int main(int argc, char *argv[]) {
    program_invocation_short_name = basename(argv[0]);

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
        log_and_exit("Error: Repeat count and Ports must be positive integers.");
    }

    // tを現在時刻で初期化
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    current_time = (uint64_t)ts.tv_sec;
    printf("Initialized current_time: %lu\n", current_time);

    char resolved_source_path[256];
    resolve_path(SOURCE_FILE, resolved_source_path, sizeof(resolved_source_path));

    // パイプを作成
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        log_and_exit("Error creating pipe: %s", strerror(errno));
    }
    fr = pipe_fds[0]; // 読み取り用
    fw = pipe_fds[1]; // 書き込み用

    // 別スレッドを作成
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, timer_thread, NULL) != 0) {
        log_and_exit("Error creating thread: %s", strerror(errno));
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
    if (file) {
        char ip[INET_ADDRSTRLEN];
        int port;
        if (fscanf(file, "%s %d", ip, &port) == 2) {
            saved_client_addr.sin_family = AF_INET;
            saved_client_addr.sin_addr.s_addr = inet_addr(ip);
            saved_client_addr.sin_port = htons(port);
            printf("Loaded source: %s:%d\n", ip, port);
        }
        fclose(file);
    }

    // 待ち受け用ソケットの作成
    if ((listen_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        log_and_exit("Error creating listen socket: %s", strerror(errno));
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        log_and_exit("Error binding listen socket: %s", strerror(errno));
    }

    // 転送用ソケットの作成
    if ((forward_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        log_and_exit("Error creating forward socket: %s", strerror(errno));
    }

    // サーバー名をIPv4アドレスに解決
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", forward_port);

    if (getaddrinfo(forward_host, port_str, &hints, &res) != 0) {
        log_and_exit("Error resolving forward address: %s", strerror(errno));
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
        log_and_exit("Error binding forward socket: %s", strerror(errno));
    }

    printf("Listening on port %d and forwarding to %s:%d\n", listen_port, forward_host, forward_port);


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
            log_message("Error in select: %s", strerror(errno));
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
            printf("Updated current_time: %lu\n", current_time);
        }

        struct Packet packet;
        if (FD_ISSET(listen_sock, &read_fds)) {
            // 待ち受けソケットからパケットを受信
            if (recvFrom(&packet, listen_sock, &client_addr, &addr_len) < 0) {
                log_message("Error receiving packet on listen socket: %s", strerror(errno));
                continue;
            }

            printf("Received packet from %s:%d, forwarding...\n",
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
            if (recvFrom(&packet, forward_sock, NULL, NULL) < 0){
                log_message("Error receiving packet on forward socket: %s", strerror(errno));
                continue;
            }

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
                        printf("Skipping get_url: Last call detected %lu seconds ago.\n", current_time - last_call_time);
                        continue;
                    }
            
                    // 前回の着信検出時刻を更新
                    last_call_time = current_time;
            
                    // URL情報をスレッドに渡すために構造体を作成
                    UrlInfo *url_info = malloc(sizeof(UrlInfo));
                    if (!url_info) {
                        log_message("Error allocating memory for URL info: %s", strerror(errno));
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
                        log_message("Error creating thread for get_url: %s", strerror(errno));
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

