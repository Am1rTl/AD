#ifndef DNSER_DB_H
#define DNSER_DB_H

#include <stdbool.h>

#define AUTH_TOKEN_LEN 36
#define MAX_FIELD_LEN 32
#define QUERY_LEN 256

typedef char (uuid_t)[AUTH_TOKEN_LEN];

#define PRICE_IP 100
#define PRICE_DNS 200
#define MIN_PRICE_REVERSE_DNS 1337

void psql_connect();

void psql_disconnect();

void create_user(const char *name);

bool is_user_exists(const char *name);

bool is_token_exists(const uuid_t);

bool get_auth_token(const char *name, const char *pass, char *token);

void setup_pass(const char *name, const char *pass);

int get_money(const uuid_t);

void set_money(const uuid_t, int money);

bool is_ip_taken(const char *ip_addr);

void buy_ip(const uuid_t uuid, const struct in_addr *ip_addr);

void buy_dns(const uuid_t, const struct in_addr *ip_addr, const char *dns);

void dns_resolve(const uuid_t, const char *dns);

void dns_reverse_resolve(const struct in_addr *ip_addr);

void show_users(void);

void show_my_ips(const uuid_t);

void show_my_domains(const uuid_t);


#endif //DNSER_DB_H
