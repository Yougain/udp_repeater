#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <netdb.h> // getaddrinfoを使用するために必要
#include <stdint.h> // uint32_tを使用するために必要
#include <pthread.h> // スレッドを使用するために必要
#include <time.h>    // UNIX時刻を取得するために必要
#include <linux/time.h>

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

struct __attribute__((packed)) UnarrivedInfoPacket {
    uint16_t packet_len; // パケットサイズ
    uint64_t time; // 時刻
    uint32_t sno; // = -1; シリアル番号
    uint32_t unarrived[1024]; // 到着していないパケット番号を格納する配列
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
    tp->sno = sno_network_order; // ネットワークバイトオーダーのシリアル番号を格納
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
    if (llabs((int64_t)(time_stamp - current_time)) > 60) {
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
        unrarrivedInfoPacket->unarrived[j++] = (u_int32_t)-1; // 到着していないパケット番号の終端を示す
        unrarrivedInfoPacket->packet_len = sizeof(uint64_t) + sizeof(uint32_t) + j * sizeof(uint32_t); // パケットサイズを計算
        unrarrivedInfoPacket->sno = htonl(-1); // ネットワークバイトオーダーで-1を格納
        unrarrivedInfoPacket->time = htobe64(current_time); // ネットワークバイトオーダーのUNIX時刻を格納
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


void send_packet(int sock, struct sockaddr_in* addr, struct Packet* packet) {
    ssize_t sent_len = sendto(sock, packet->data, packet->packet_len, 0,
                            (struct sockaddr *)addr, sizeof(*addr));
    if (sent_len < 0) {
        perror("sendto");
    } else {
        printf("Sent packet with timestamp %lu and sno %u to forward destination.\n", current_time, packet_sno - 1);
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
            for(uint32_t* ptr = &requestPacket->unarrived; *ptr != (uint32_t)-1; ++ptr) {
                uint32_t i = *ptr;
                if (i < packet_sno - 1024 || packet_sno <= i) {
                    // 到着していないパケット番号が範囲外の場合
                    printf("Invalid unarrived packet number: %u\n", i);
                    continue;
                }
                // 到着していないパケットを再送する
                send_packet(peer_sock, peer_addr, (struct Packet*)taggedPacketPtr(i));
            }
            return;
        }
        printf("Received valid packet from forward destination, sending back to source...\n");
        if (addr->sin_port != 0)
            for (size_t i = rpacket_index_bottom; i < rpacket_index_bottom + pktCount; ++i){
                // 転送先にパケットを送信
                if(!isUnarrivedMax(i)) // 再送要求限度を超えても到着していないパケット番号をスキップ
                    send_packet(sock, addr, (struct Packet*)bufferedPacketPtr(i));
            }
        if (unrarrivedInfoPacket.packet_len > 0) {
            // 到着していないパケット番号を返送
            send_packet(peer_sock, peer_addr, (struct Packet*)&unrarrivedInfoPacket);
        }
    }else{
        // パケットサイズとUNIX時刻とシリアル番号を付加する
        // packet_snoをインクリメント
        add_timestamp_and_sno(packet);
        pktCount = 1;
        send_packet(sock, addr, (struct Packet*)taggedPacketPtr(packet_sno - 1)); // taggedPacketsのポインタを取得
    }

}


int main(int argc, char *argv[]) {
    // PACKET_SIZEバイトを1024個収容可能なバッファを作成してゼロで初期化

    // コマンドライン引数を解析
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0) {
            is_server_mode = 1;
            break;
        }
    }

    if (argc < 5 || (is_server_mode && argc != 6)) {
        fprintf(stderr, "Usage: %s [--server] <listen_port> <bind_port> <forward_host> <forward_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // コマンドライン引数から設定を取得
    int listen_port = atoi(argv[is_server_mode ? 2 : 1]);
    int bind_port = atoi(argv[is_server_mode ? 3 : 2]);
    const char *forward_host = argv[is_server_mode ? 4 : 3];
    int forward_port = atoi(argv[is_server_mode ? 5 : 4]);

    if (listen_port <= 0 || bind_port <= 0 || forward_port <= 0) {
        fprintf(stderr, "Error: Ports must be positive integers.\n");
        exit(EXIT_FAILURE);
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
        perror("pipe");
        exit(EXIT_FAILURE);
    }
    fr = pipe_fds[0]; // 読み取り用
    fw = pipe_fds[1]; // 書き込み用

    // 別スレッドを作成
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, timer_thread, NULL) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
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
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        close(listen_sock);
        exit(EXIT_FAILURE);
    }

    // 転送用ソケットの作成
    if ((forward_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        close(listen_sock);
        exit(EXIT_FAILURE);
    }

    // サーバー名をIPv4アドレスに解決
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", forward_port);

    if (getaddrinfo(forward_host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        close(listen_sock);
        close(forward_sock);
        exit(EXIT_FAILURE);
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
        perror("bind");
        close(listen_sock);
        close(forward_sock);
        exit(EXIT_FAILURE);
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
            perror("select");
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
                perror("recvfrom");
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
                perror("recvfrom");
                continue;
            }

            trans_packet(!is_server_mode, listen_sock, &saved_client_addr, &packet, forward_sock, &forward_addr);
        }
    }

    close(listen_sock);
    close(forward_sock);
    close(fr);
    close(fw);
    return 0;
}

