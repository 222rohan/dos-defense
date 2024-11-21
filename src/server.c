//c program to make a server which 
// detects icmp flood attack
// by calculating the running rate
// using raw socket
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <time.h>
#include <stdbool.h>
#include <netinet/tcp.h>


#define RATE_LIMIT_FACTOR 3       // Rate limit threshold multiplier
#define BLOCK_DURATION 10         // Block ICMP handling for 10 seconds on attack
#define STARTUP_LIMIT 100         // Max ICMP requests/sec during startup
#define GRACE_PERIOD 5            // Grace period for startup in seconds
#define LOG_FILE_PATH_ICMP "./icmp_traffic.log"
#define LOG_FILE_PATH_SYN "./tcp_traffic.log"
#define DEST_PORT 8080
#define MAX_BUFFER 65536

int request_count = 0;           // Count of requests received
time_t start_timer      ;    // Start time for rate calculation
double prev_rate = 0.0;

int total_req = 0;

bool is_blocked = false;        // Flag indicating ICMP blocking
time_t block_end_time ;      // Time to resume after blocking
time_t server_start_time;   // Server startup time


// Calculate the running average request rate
double calculate_request_rate() {
    return (double)request_count;
}

// Log a message to the log file
void log_event(const char *message, int type) {
    if(type == 0) { // icmp logs
        FILE *log_file = fopen(LOG_FILE_PATH_ICMP, "a");
        if (log_file == NULL) {
            perror("Failed to open log file");
            exit(EXIT_FAILURE); // Ensure logging issues are immediately visible
        }

        time_t now ;
        time(&now);
        char *time_str = ctime(&now);
        time_str[strcspn(time_str, "\n")] = 0; // Remove newline from ctime
        fprintf(log_file, "[%s] %s\n", time_str, message);
        fclose(log_file);
    }
    else if(type == 1) { // syn logs
        FILE *log_file = fopen(LOG_FILE_PATH_SYN, "a");
        if (log_file == NULL) {
            perror("Failed to open log file");
            exit(EXIT_FAILURE); // Ensure logging issues are immediately visible
        }

        time_t now ;
        time(&now);
        char *time_str = ctime(&now);
        time_str[strcspn(time_str, "\n")] = 0; // Remove newline from ctime
        fprintf(log_file, "[%s] %s\n", time_str, message);
        fclose(log_file);
    }
}

// Initiate ICMP blocking
void initiate_block() {
    is_blocked = true;
    block_end_time = time(&block_end_time) + BLOCK_DURATION;
    printf("Suspected ICMP flood detected! Blocking ICMP traffic for %d seconds.\n", BLOCK_DURATION);
	char buf[100];
	sprintf(buf,"Suspected ICMP flood detected! Blocking ICMP traffic for %d seconds.\n", BLOCK_DURATION);
    log_event(buf,0);
}

void *handle_icmp(void *arg) {
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_sock < 0) {
        perror("ICMP socket creation failed");
        exit(EXIT_FAILURE);
    }

    char buffer[65536];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

     time(&server_start_time);
    printf("[+] Server start time: %s", ctime(&server_start_time)); // Print server start time
    log_event("Server started.",0);

    time(&start_timer);
    while (1) {
        // Check if blocking is active
        if (is_blocked) {
            if (time(NULL) >= block_end_time) {
                is_blocked = false;
                printf("Resuming ICMP processing after block period.\n");
                log_event("Resumed ICMP processing after block period.",0);
            } else {
                // Ignore ICMP packets during block period
                continue;
            }
        }


        int len = recvfrom(raw_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len);
        if (len < 0) {
            perror("Error receiving ICMP packet");
            continue;
        } else {
            request_count++;
            total_req++;
        }

        double avg_rate = 0.0;
        
        // Compute running average rate
	time_t elapsed;
    time(&elapsed);
        if (difftime(elapsed, start_timer) >= 1) {
            avg_rate = calculate_request_rate();
            printf("Running average rate: %.2f requests/sec\n", avg_rate);
		    char buf[100];
            sprintf(buf, "Running average rate: %.2f requests/sec\n", avg_rate);
	        log_event(buf,0);
            time(&start_timer);
            request_count = 0;
		
        }
        double threshold = prev_rate * RATE_LIMIT_FACTOR;
	if(threshold == 0) threshold = 200;
	prev_rate = avg_rate;
		if(prev_rate > STARTUP_LIMIT) {
		    prev_rate = STARTUP_LIMIT;
		}
        

        // Determine if we are in the grace period
        time_t current_time ;
         time(&current_time);
        // printf("%f",difftime(current_time, server_start_time));
	
        if (difftime(current_time, server_start_time) < GRACE_PERIOD) {
            // Apply startup limit
            if (avg_rate > STARTUP_LIMIT) {
                printf("Immediate ICMP flood detected during startup! Blocking traffic.\n");
                log_event("Immediate ICMP flood detected during startup! Blocking traffic.",0);
                initiate_block();
                continue;
            }
        } else {
            // Apply running average threshold after grace period
            if ((avg_rate > threshold )&& (avg_rate > STARTUP_LIMIT)) {
                printf("ICMP flood detected! Blocking traffic.[%f]\n",avg_rate);
                log_event("ICMP flood detected! Blocking traffic.",0);
                initiate_block();
                continue;
            }
        }
        
        // Process ICMP packet (Example: Echo Reply)
        struct iphdr *ip_header = (struct iphdr *)buffer;
        struct icmphdr *icmp_header = (struct icmphdr *)(buffer + (ip_header->ihl * 4));

        if (icmp_header->type == ICMP_ECHO) {
            printf("ICMP Echo Request received from %s\n",
                   inet_ntoa(addr.sin_addr));

            // Send Echo Reply
            icmp_header->type = ICMP_ECHOREPLY;
            if (sendto(raw_sock, buffer, len, 0, (struct sockaddr *)&addr, addr_len) < 0) {
                perror("Error sending ICMP Echo Reply");
            }
        }
    }
}


// Function to calculate checksum
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

// Print an IP address
void print_ip(struct in_addr ip) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
    printf("%s", ip_str);
}

void *handle_syn(void *arg) {
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        perror("TCP raw socket creation failed");
        exit(EXIT_FAILURE);
    }

    char buffer[65536];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    time(&server_start_time);
    log_event("Server started.",1);

    time(&start_timer);
    while (1) {
        if (is_blocked) {
            if (time(NULL) >= block_end_time) {
                is_blocked = false;
                printf("Resuming SYN processing after block period.\n");
                log_event("Resumed SYN processing after block period.",1);
            } else {
                // Ignore TCP packets during block period
                continue;
            }
        }

        int len = recvfrom(raw_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len);
        if (len < 0) {
            perror("Error receiving TCP packet");
            continue;
        } else {
            request_count++;
            total_req++;
        }

        double avg_rate = 0.0;

        // Compute running average rate
        time_t elapsed;
        time(&elapsed);
        if (difftime(elapsed, start_timer) >= 1) {
            avg_rate = (double)request_count / difftime(elapsed, start_timer);
            printf("Running average SYN rate: %.2f SYN packets/sec\n", avg_rate);
            char buf[100];
            sprintf(buf, "Running average SYN rate: %.2f SYN packets/sec\n", avg_rate);
            log_event(buf,1);
            time(&start_timer);
            request_count = 0;
        }

        double threshold = prev_rate * RATE_LIMIT_FACTOR;
        if (threshold == 0) threshold = 200;
        prev_rate = avg_rate;
        if (prev_rate > STARTUP_LIMIT) {
            prev_rate = STARTUP_LIMIT;
        }

        time_t current_time;
        time(&current_time);

        if (difftime(current_time, server_start_time) < GRACE_PERIOD) {
            if (avg_rate > STARTUP_LIMIT) {
                printf("Immediate SYN flood detected during startup! Blocking traffic.\n");
                log_event("Immediate SYN flood detected during startup! Blocking traffic.",1);
                is_blocked = true;
                block_end_time = time(NULL) + 10;  // Block for 10 seconds
                continue;
            }
        } else {
            if ((avg_rate > threshold) && (avg_rate > STARTUP_LIMIT)) {
                printf("SYN flood detected! Blocking traffic. [%.2f]\n", avg_rate);
                log_event("SYN flood detected! Blocking traffic.",1);
                is_blocked = true;
                block_end_time = time(NULL) + 10;  // Block for 10 seconds
                continue;
            }
        }

        // Process SYN packet
        struct iphdr *ip_header = (struct iphdr *)buffer;
        struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl * 4));

        if (tcp_header->syn && !tcp_header->ack) {
            printf("SYN packet received from %s\n",
                   inet_ntoa(addr.sin_addr));
            printf("Sending SYN-ACK packet to %s\n",
                   inet_ntoa(addr.sin_addr));
        }
    }
}

void *handle_ack() {
    while(1) {
        if(is_blocked) continue;

        //listen for incoming connections
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Failed to create socket");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(DEST_PORT);
        server_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Failed to bind socket");
            exit(EXIT_FAILURE);
        }

        if (listen(sockfd, 5) < 0) {
            perror("Failed to listen on socket");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Failed to accept connection");
            exit(EXIT_FAILURE);
        }

        printf("Connection established with %s\n", inet_ntoa(client_addr.sin_addr));
        log_event("Connection established with client.",1);
        close(client_sock);
    }
}


int main() {
    // Clear the log file at startup
    FILE *log_file = fopen(LOG_FILE_PATH_ICMP, "w");
    if (log_file) {
        fclose(log_file);
    } else {
        perror("Failed to create/clear log file at startup");
        exit(EXIT_FAILURE);
    }

    FILE *log_file_syn = fopen(LOG_FILE_PATH_SYN, "w");
    if (log_file_syn) {
        fclose(log_file_syn);
    } else {
        perror("Failed to create/clear log file at startup");
        exit(EXIT_FAILURE);
    }

    log_event("Server started.", 0);
    log_event("Server started.", 1);

    pthread_t icmp_thread, syn_thread, tcp_thread;
    if (pthread_create(&icmp_thread, NULL, handle_icmp, NULL) != 0) {
        perror("Failed to create ICMP handler thread");
        exit(EXIT_FAILURE);
    }
    
    if (pthread_create(&syn_thread, NULL, handle_syn, NULL) != 0) {
        perror("Failed to create SYN handler thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&tcp_thread, NULL, handle_ack, NULL) != 0) {
        perror("Failed to create SYN handler thread");
        exit(EXIT_FAILURE);
    }

    pthread_join(syn_thread, NULL);
    pthread_join(icmp_thread, NULL);
    pthread_join(tcp_thread, NULL);
    return 0;
}