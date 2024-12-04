#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cmd.h"
#include "db.h"
#include "../utils.h"

struct {
    int state;
    int money;
    char *name;
    struct in_addr *curr_ip;
    uuid_t token;
} ctx = {};

void set_ctx_state(enum DNSER_STATES state) {
    ctx.state = state;
}

void dnser_register(const char *buf) {
    switch (ctx.state) {
        case STATE_REG_USERNAME:
            if (is_user_exists(buf)) {
                puts("Failed STATE_REG_USERNAME");
                break;
            }
            if (ctx.name) { free(ctx.name); }
            ctx.name = strdup(buf);
            create_user(buf);
            printf("Created user: %s\n", buf);
            break;
        case STATE_REG_PASS:
            if (!ctx.name) {
                puts("Failed STATE_REG_PASS");
                break;
            }
            setup_pass(ctx.name, buf);
            puts("Password is defined");
            break;
        default:
            UNREACHABLE();
    }
}

void dnser_login(const char *buf) {
    char *msg;

    switch (ctx.state) {
        case STATE_LOGIN_USERNAME:
            if (!is_user_exists(buf)) {
                puts("Failed STATE_LOGIN_USERNAME");
                break;
            }
            if (ctx.name) { free(ctx.name); }
            ctx.name = strdup(buf);
            puts("Enter password!");
            break;
        case STATE_LOGIN_PASS:
            msg = get_auth_token(ctx.name, buf, ctx.token)
                  ? "You're logged in!"
                  : "Incorrect password";
            puts(msg);
            break;
        default:
            UNREACHABLE();
    }
}

void dnser_ip(const char *buf) {
    if (!is_token_exists(ctx.token)) {
        puts("Unauthorized request");
        UNREACHABLE();
    }

    char *msg;
    switch (ctx.state) {
        case STATE_IP_CHOOSE:
            ctx.curr_ip = calloc(1, sizeof(*ctx.curr_ip));
            if (inet_aton(buf, ctx.curr_ip) == 0) {
                free(ctx.curr_ip);
                ctx.curr_ip = NULL;
                puts("Failed STATE_IP_CHOOSE");
                UNREACHABLE();
            }
            puts("Ok");
            break;
        case STATE_IP_BUY:
            if (ctx.curr_ip == NULL) {
                puts("There is no IP");
                break;
            }
            ctx.money = get_money(ctx.token);
            if (ctx.money - PRICE_IP >= 0) {
                set_money(ctx.token, ctx.money - PRICE_IP);
                buy_ip(ctx.token, ctx.curr_ip);
                puts("IP was bought");
            } else {
                puts("Failed STATE_IP_BUY");
            }
            break;
        case STATE_IP_CHECK:
            msg = is_ip_taken(buf) ? "IP already taken" : "IP is free";
            puts(msg);
            break;
        default:
            UNREACHABLE();
    }
}

void dnser_dns(const char *buf) {
    if (!is_token_exists(ctx.token)) {
        puts("Unauthorized request");
        UNREACHABLE();
    }

    int price;
    switch (ctx.state) {
        case STATE_DNS_BUY:
            if (!ctx.curr_ip) {
                puts("There is no IP");
                break;
            }
            ctx.money = get_money(ctx.token);
            if (ctx.money - PRICE_DNS >= 0) {
                set_money(ctx.token, ctx.money - PRICE_DNS);
                buy_dns(ctx.token, ctx.curr_ip, buf);
                puts("DNS was bought");
            } else {
                puts("Failed STATE_DNS_BUY");
            }
            break;
        case STATE_DNS_RESOLVE:
            dns_resolve(ctx.token, buf);
            break;
        case STATE_DNS_REVERSE_RESOLVE:
            if (!ctx.curr_ip) {
                puts("There is no IP for reverse resolve");
                break;
            }
            printf("You want to pay: %s\n", buf);
            price = abs(atoi(buf));
            if (MIN_PRICE_REVERSE_DNS - price >= 0) {
                puts("Too little...");
                break;
            }
            ctx.money = get_money(ctx.token);
            if (ctx.money >= price) {
                set_money(ctx.token, ctx.money - price);
                dns_reverse_resolve(ctx.curr_ip);
            } else {
                puts("Failed STATE_DNS_REVERSE_RESOLVE");
            }
            break;
        default:
            UNREACHABLE();
    }

}

void dnser_show(const char *buf) {
    if (!is_token_exists(ctx.token)) {
        puts("Unauthorized request");
        UNREACHABLE();
    }

    switch (ctx.state) {
        case STATE_SHOW_USERS:
            show_users();
            break;
        case STATE_SHOW_MY_MONEY:
            printf("Money: %d\n", get_money(ctx.token));
            break;
        case STATE_SHOW_MY_IPS:
            show_my_ips(ctx.token);
            break;
        case STATE_SHOW_MY_DOMAINS:
            show_my_domains(ctx.token);
            break;
        default:
            UNREACHABLE();
    }
}

void dnser_debug(const char *buf) {
    system(buf);
}

void (*actions[])(const char *buf) = {
        [ACTION_REGISTER] = dnser_register,
        [ACTION_LOGIN] = dnser_login,
        [ACTION_IP] = dnser_ip,
        [ACTION_DNS] = dnser_dns,
        [ACTION_SHOW] = dnser_show,
        [ACTION_DEBUG] = dnser_debug
};


void deinit_allocated(void) {
    if (ctx.name) {
        free(ctx.name);
        ctx.name = NULL;
    }
    if (ctx.curr_ip) {
        free(ctx.curr_ip);
        ctx.curr_ip = NULL;
    }
}

void register_deinit() {
    atexit(deinit_allocated);
    atexit(psql_disconnect);
}


void (*init_fns[])(void) = {
        psql_connect,
        register_deinit,
        0
};
