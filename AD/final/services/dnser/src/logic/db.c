#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <libpq-fe.h>
#include <errno.h>

#include "db.h"
#include "../utils.h"

PGconn *conn;

void psql_connect() {
    conn = PQconnectdb("dbname=dnsdb user=postgres host="PATH_TO_DB" port=5432");
    if (PQstatus(conn) != CONNECTION_OK) {
        printf("Error while connecting to the database server: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        UNREACHABLE();
    }
}

void psql_disconnect() {
    PQfinish(conn);
}

bool is_valid_userpass(const char *txt) {
    if (strlen(txt) > MAX_FIELD_LEN) {
        return false;
    }

    char letter;
    while ((letter = *txt++) != 0) {
        if (!(isdigit(letter) || islower(letter) || isupper(letter))) {
            printf("Invalid text: %s\n", txt);
            return false;
        }
    }
    return true;
}

bool is_valid_dns_name(const char *txt) {
    if (strlen(txt) > MAX_FIELD_LEN) {
        return false;
    }

    char letter;
    while ((letter = *txt++) != 0) {
        if (!(isdigit(letter) || islower(letter) || isupper(letter) || letter == '.' || letter == '=')) {
            printf("Invalid dns: %s\n", txt);
            return false;
        }
    }
    return true;
}

bool is_user_exists(const char *name) {
    if (!is_valid_userpass(name)) {
        UNREACHABLE();
    }

    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT * "
             "FROM users "
             "WHERE name='%s'",
             name);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while check user existence: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    int rows = PQntuples(res);
    PQclear(res);
    return rows != 0;
}

void create_user(const char *name) {
    if (!is_valid_userpass(name)) {
        UNREACHABLE();
    }

    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "INSERT INTO users (name) "
             "VALUES ('%s')",
             name);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        printf("Error while creating user: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    PQclear(res);
}

void setup_pass(const char *name, const char *pass) {
    if (!is_valid_userpass(name) || !is_valid_userpass(pass)) {
        UNREACHABLE();
    }

    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "UPDATE users "
             "SET passwd='%s' "
             "WHERE name='%s'",
             pass, name);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        printf("Error while setting password: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    PQclear(res);
}

bool get_auth_token(const char *name, const char *pass, char *token) {
    if (!is_valid_userpass(name) || !is_valid_userpass(pass)) {
        UNREACHABLE();
    }

    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT token "
             "FROM users "
             "WHERE name='%s' AND passwd='%s'",
             name, pass);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while get auth token: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        memset(token, 0, AUTH_TOKEN_LEN);
        return false;
    }

    memcpy(token, PQgetvalue(res, 0, 0), AUTH_TOKEN_LEN);
    PQclear(res);
    return true;
}

bool is_ip_taken(const char *ip_addr) {
    struct in_addr addr = {};
    if (inet_aton(ip_addr, &addr) == 0) {
        puts("Invalid ip address");
        UNREACHABLE();
    }

    bool is_taken = false;
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT owner_id "
             "FROM addresses "
             "WHERE ip='%s'",
             ip_addr);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while check ip addr existence: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    if (PQntuples(res) != 0) {
        is_taken = true;
        printf("Addr is taken by id: %s\n", PQgetvalue(res, 0, 0));
    }

    PQclear(res);
    return is_taken;
}

bool is_token_exists(const uuid_t uuid) {
    bool is_exists = false;
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT id "
             "FROM users "
             "WHERE token='%s'",
             uuid);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while checking token: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    if (PQntuples(res) == 1) {
        is_exists = true;
    }

    PQclear(res);
    return is_exists;
}

int get_money(const uuid_t uuid) {
    int money;
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT money "
             "FROM users "
             "WHERE token='%s'",
             uuid);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while getting money: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    if (PQntuples(res) != 1) {
        PQclear(res);
        UNREACHABLE();
    }

    money = (int) strtol(PQgetvalue(res, 0, 0), 0, 0);
    if (errno == ERANGE) {
        puts("Convert string to money error");
        PQclear(res);
        UNREACHABLE();
    }

    PQclear(res);
    return money;
}

void set_money(const uuid_t uuid, int money) {
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "UPDATE users "
             "SET money='%d' "
             "WHERE token='%s'",
             money, uuid);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        printf("Error while setting money: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    PQclear(res);
}

void buy_ip(const uuid_t uuid, const struct in_addr *ip_addr) {
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "INSERT INTO addresses (owner_id, ip) "
             "VALUES ((SELECT id FROM users WHERE token='%s'), '%s')",
             uuid, inet_ntoa(*ip_addr));

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        printf("Error while buying ip: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    PQclear(res);
}

void buy_dns(const uuid_t uuid, const struct in_addr *ip_addr, const char *dns) {
    if (!is_valid_dns_name(dns)) {
        UNREACHABLE();
    }

    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "INSERT INTO domains (ip_id, name) "
             "VALUES ( "
                "(SELECT a.id "
                "FROM addresses a "
                "JOIN users u ON a.owner_id = u.id "
                "WHERE u.token='%s' AND a.ip='%s'), "
                "'%s'"
            ")",
             uuid, inet_ntoa(*ip_addr), dns);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        printf("Error while buying ip: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }
    PQclear(res);
}

void dns_resolve(const uuid_t uuid, const char *dns) {
    if (!is_valid_dns_name(dns)) {
        UNREACHABLE();
    }

    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT a.ip "
             "FROM addresses a "
             "JOIN users u ON a.owner_id = u.id "
             "JOIN domains d ON a.id = d.ip_id "
             "WHERE u.token='%s' AND d.name='%s'",
             uuid, dns);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while resolving dns: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    printf("Resolve result: %s\n", PQgetvalue(res, 0, 0));
    PQclear(res);
}

void dns_reverse_resolve(const struct in_addr *ip_addr) {
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT d.name "
             "FROM domains d "
             "JOIN addresses a ON d.ip_id = a.id "
             "WHERE a.ip='%s'",
             inet_ntoa(*ip_addr));

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while reverse resolving dns: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    puts("Reverse resolve results:\n");
    for (int i = 0; i < PQntuples(res); ++i) {
        printf("%s\n", PQgetvalue(res, i, 0));
    }
    PQclear(res);
}

void show_users(void) {
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT u.name, a.ip "
             "FROM users u "
             "JOIN addresses a ON u.id = a.owner_id");

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while showing users: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    puts("Users: ");
    for (int i = 0; i < PQntuples(res); ++i) {
        printf("%s|%s\n", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1)); // name|ip
    }
    PQclear(res);
}

void show_my_ips(const uuid_t uuid) {
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT a.ip "
             "FROM users u "
             "JOIN addresses a ON u.id = a.owner_id "
             "WHERE u.token='%s'",
             uuid);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while showing users: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    puts("My addresses: ");
    for (int i = 0; i < PQntuples(res); ++i) {
        printf("%s\n", PQgetvalue(res, i, 0)); // name|ip
    }
    PQclear(res);
}

void show_my_domains(const uuid_t uuid) {
    char query[QUERY_LEN] = {};
    snprintf(query, QUERY_LEN,
             "SELECT d.name, a.ip "
             "FROM users u "
             "JOIN addresses a ON a.owner_id = u.id "
             "JOIN domains d ON a.id = d.ip_id "
             "WHERE u.token='%s'",
             uuid);

    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        printf("Error while showing users: %s\n", PQerrorMessage(conn));
        PQclear(res);
        UNREACHABLE();
    }

    puts("My domains: ");
    for (int i = 0; i < PQntuples(res); ++i) {
        printf("%s|%s\n", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1)); // domain|ip
    }
    PQclear(res);
}

