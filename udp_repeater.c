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

#define BUFFER_SIZE 65536
#define SOURCE_FILE "~/.udp_repeater_source"

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

void add_timestamp_and_counter(char *buffer, ssize_t *recv_len, uint64_t timestamp, uint32_t *counter) {
    uint64_t timestamp_network_order = htobe64(timestamp); // ネットワークバイトオーダーに変換
    uint32_t counter_network_order = htonl(*counter); // ネットワイトオーダーに変換

    memmove(buffer + sizeof(uint64_t) + sizeof(uint32_t), buffer, *recv_len); // データを後ろにずらす
    memcpy(buffer, &timestamp_network_order, sizeof(uint64_t)); // UNIX時刻を先頭に追加
    memcpy(buffer + sizeof(uint64_t), &counter_network_order, sizeof(uint32_t)); // カウンターを追加
    *recv_len += sizeof(uint64_t) + sizeof(uint32_t); // パケットサイズを更新
    (*counter)++; // カウンターをインクリメント
}

// パケットの先頭64ビットをUNIX時刻として解釈し、判定する関数
// 60秒以上ずれていない場合は、先頭のUNIX時刻と32ビットカウンターを削除
int validate_and_strip_packet(char *buffer, ssize_t *len, uint64_t current_time) {
    if (*len < sizeof(uint64_t) + sizeof(uint32_t)) {
        printf("Dropped packet: too small to contain a valid timestamp and counter.\n");
        return 0; // 無効なパケット
    }

    uint64_t received_timestamp;
    memcpy(&received_timestamp, buffer, sizeof(uint64_t));
    received_timestamp = be64toh(received_timestamp); // ネットワークバイトオーダーをホストバイトオーダーに変換

    // 現在の時刻と比較
    if (llabs((int64_t)(received_timestamp - current_time)) > 60) {
        printf("Dropped packet: timestamp %lu is out of sync with current time %lu.\n",
               received_timestamp, current_time);
        return 0; // 無効なパケット
    }

    // パケットの先頭からUNIX時刻とカウンターを削除
    memmove(buffer, buffer + sizeof(uint64_t) + sizeof(uint32_t), *len - (sizeof(uint64_t) + sizeof(uint32_t)));
    *len -= sizeof(uint64_t) + sizeof(uint32_t); // パケットサイズを更新

    return 1; // 有効なパケット
}

int fr, fw; // パイプの読み取り用と書き込み用
uint64_t t; // 64ビットのUNIX時刻を格納する変数

// 別スレッドで10秒ごとにfwに'\0'を書き込む関数
void *timer_thread(void *arg) {
    while (1) {
        sleep(10); // 10秒待機
        char dummy = '\0';
        write(fw, &dummy, 1); // fwに1バイト書き込む
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int is_server_mode = 0;

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
    t = (uint64_t)ts.tv_sec;
    printf("Initialized timestamp: %lu\n", t);

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
    char buffer[BUFFER_SIZE];
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

    uint32_t packet_counter = 0; // カウンターを初期化

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
            t = (uint64_t)ts.tv_sec;
            printf("Updated timestamp: %lu\n", t);
        }

        if (FD_ISSET(listen_sock, &read_fds)) {
            // 待ち受けソケットからパケットを受信
            ssize_t recv_len = recvfrom(listen_sock, buffer, BUFFER_SIZE - sizeof(uint64_t) - sizeof(uint32_t), 0,
                                        (struct sockaddr *)&client_addr, &addr_len);
            if (recv_len < 0) {
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

            if (is_server_mode) {
                // パケットを検証して先頭のUNIX時刻とカウンターを削除
                if (!validate_and_strip_packet(buffer, &recv_len, t)) {
                    continue; // 無効なパケットを破棄
                }

                printf("Received valid packet from forward destination, sending back to source...\n");
            }else{
                // UNIX時刻とカウンターを付加して転送
                add_timestamp_and_counter(buffer, &recv_len, t, &packet_counter);
            }

            ssize_t sent_len = sendto(forward_sock, buffer, recv_len, 0,
                                      (struct sockaddr *)&forward_addr, sizeof(forward_addr));
            if (sent_len < 0) {
                perror("sendto");
            } else {
                printf("Sent packet with timestamp %lu and counter %u to forward destination.\n", t, packet_counter - 1);
            }
        }

        if (FD_ISSET(forward_sock, &read_fds)) {
            // 転送用ソケットからパケットを受信
            ssize_t recv_len = recvfrom(forward_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
            if (recv_len < 0) {
                perror("recvfrom");
                continue;
            }

            if (!is_server_mode) {
                // パケットを検証して先頭のUNIX時刻とカウンターを削除
                if (!validate_and_strip_packet(buffer, &recv_len, t)) {
                    continue; // 無効なパケットを破棄
                }

                printf("Received valid packet from forward destination, sending back to source...\n");
            }else{
                // UNIX時刻とカウンターを付加して転送
                add_timestamp_and_counter(buffer, &recv_len, t, &packet_counter);
            }

            // 送信元に返送
            if (saved_client_addr.sin_port != 0) {
                ssize_t sent_len = sendto(listen_sock, buffer, recv_len, 0,
                                          (struct sockaddr *)&saved_client_addr, sizeof(saved_client_addr));
                if (sent_len < 0) {
                    perror("sendto");
                }
            } else {
                printf("No source address available to send back to.\n");
            }
        }
    }

    close(listen_sock);
    close(forward_sock);
    close(fr);
    close(fw);
    return 0;
}

