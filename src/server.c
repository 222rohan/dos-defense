//c program to make a server which 
// detects icmp flood attack
// by calculate the running rate
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

#define RATE_LIMIT_FACTOR 3       // Rate limit threshold multiplier
#define BLOCK_DURATION 10         // Block ICMP handling for 10 seconds on attack
#define STARTUP_LIMIT 100         // Max ICMP requests/sec during startup
#define GRACE_PERIOD 5            // Grace period for startup in seconds
#define LOG_FILE_PATH "./icmp_attack.log"

int request_count = 0;           // Count of requests received
time_t start_timer      ;    // Start time for rate calculation

int total_req = 0;

bool is_blocked = false;        // Flag indicating ICMP blocking
time_t block_end_time ;      // Time to resume after blocking
time_t server_start_time;   // Server startup time

// Calculate the running average request rate
double calculate_request_rate() {
    return (double)request_count;
}

// Log a message to the log file
void log_event(const char *message) {
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
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

// Initiate ICMP blocking
void initiate_block() {
    is_blocked = true;
    block_end_time = time(&block_end_time) + BLOCK_DURATION;
    printf("Suspected ICMP flood detected! Blocking ICMP traffic for %d seconds.\n", BLOCK_DURATION);
	char buf[100];
	sprintf(buf,"Suspected ICMP flood detected! Blocking ICMP traffic for %d seconds.\n", BLOCK_DURATION);
    log_event(buf);
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
    log_event("Server started.");

    time(&start_timer);
    while (1) {
        // Check if blocking is active
        if (is_blocked) {
            if (time(NULL) >= block_end_time) {
                is_blocked = false;
                printf("Resuming ICMP processing after block period.\n");
                log_event("Resumed ICMP processing after block period.");
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
        double prev_rate = 0.0;
        // Compute running average rate
	time_t elapsed;
    time(&elapsed);
        if (difftime(elapsed, start_timer) >= 1) {
            avg_rate = calculate_request_rate();
            printf("Running average rate: %.2f requests/sec\n", avg_rate);
		    char buf[100];
            sprintf(buf, "Running average rate: %.2f requests/sec\n", avg_rate);
	        log_event(buf);
            time(&start_timer);
            request_count = 0;
        }
        double threshold = prev_rate * RATE_LIMIT_FACTOR;
        

        // Determine if we are in the grace period
        time_t current_time ;
         time(&current_time);
         printf("%f",difftime(current_time, server_start_time));
        if (difftime(current_time, server_start_time) < GRACE_PERIOD) {
            // Apply startup limit
            if (avg_rate > STARTUP_LIMIT) {
                printf("Immediate ICMP flood detected during startup! Blocking traffic.\n");
                log_event("Immediate ICMP flood detected during startup! Blocking traffic.");
                initiate_block();
                continue;
            }
        } else {
            // Apply running average threshold after grace period
            if (avg_rate > threshold && total_req > STARTUP_LIMIT) {
                printf("ICMP flood detected! Blocking traffic.[%f vs %f]\n",avg_rate, threshold);
                log_event("ICMP flood detected! Blocking traffic.");
                initiate_block();
                continue;
            }
        }
        prev_rate = avg_rate;
        if(prev_rate > STARTUP_LIMIT) {
            prev_rate = STARTUP_LIMIT;
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

int main() {
    // Clear the log file at startup
    FILE *log_file = fopen(LOG_FILE_PATH, "w");
    if (log_file) {
        fclose(log_file);
    } else {
        perror("Failed to create/clear log file at startup");
        exit(EXIT_FAILURE);
    }

    pthread_t icmp_thread;
    if (pthread_create(&icmp_thread, NULL, handle_icmp, NULL) != 0) {
        perror("Failed to create ICMP handler thread");
        exit(EXIT_FAILURE);
    }

    pthread_join(icmp_thread, NULL);
    return 0;
}
