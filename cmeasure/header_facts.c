/* header_facts: emit authoritative protocol header/field widths (in bits) from
 * the system <netinet/*> struct definitions, as JSON, for cross-checking the
 * survey catalog's bit accounting.
 *
 * Measurement only: this reports sizeof/offsetof facts about header layouts.
 * It performs no packet construction, transmission, or I/O. */
#define _DEFAULT_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int main(void) {
    printf("{\n");
    printf("  \"ipv4_header_bits\": %zu,\n", sizeof(struct ip) * 8u);
    printf("  \"ipv4_id_bits\": %zu,\n", sizeof(((struct ip *)0)->ip_id) * 8u);
    printf("  \"tcp_header_bits\": %zu\n", sizeof(struct tcphdr) * 8u);
    printf("}\n");
    return 0;
}
