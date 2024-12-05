#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "logic/cmd.h"
#include "utils.h"

void call_init_funcs() {
    void (**fn)(void);
    for (fn = init_fns; (*fn) != 0; fn++)
        (*fn)();
}

void welcome_msg() {
    puts("Welcome to\n");
    puts("$$$$$$$\\  $$\\   $$\\  $$$$$$\\  $$$$$$$$\\ $$$$$$$\\  ");
    puts("$$  __$$\\ $$$\\  $$ |$$  __$$\\ $$  _____|$$  __$$\\ ");
    puts("$$ |  $$ |$$$$\\ $$ |$$ /  \\__|$$ |      $$ |  $$ |");
    puts("$$ |  $$ |$$ $$\\$$ |\\$$$$$$\\  $$$$$\\    $$$$$$$  |");
    puts("$$ |  $$ |$$ \\$$$$ | \\____$$\\ $$  __|   $$  __$$< ");
    puts("$$ |  $$ |$$ |\\$$$ |$$\\   $$ |$$ |      $$ |  $$ |");
    puts("$$$$$$$  |$$ | \\$$ |\\$$$$$$  |$$$$$$$$\\ $$ |  $$ |");
    puts("\\_______/ \\__|  \\__| \\______/ \\________|\\__|  \\__|");
    puts("\n");
}

int main() {
    char buf[MAX_BUF_SIZE + 1] = {};
    char *buf_end;
    int ret;
    void (*action_fn)(const char *buf);
    enum DNSER_ACTIONS action;
    enum DNSER_STATES state;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    call_init_funcs();

    welcome_msg();

    do {
        ret = scanf("%d|%d|%" STR(MAX_BUF_SIZE) "[^\n]", (int *) &action, (int *) &state, buf);
        // If third arg is optional, so use "stub" in exploit
        if (ret != 3) {
            continue;
        }
        buf_end = strpbrk(buf, "\n");
        if (buf_end != NULL) {
            *buf_end = 0;
        }
        if (action == ACTION_EXIT) {
            break;
        }
        if (action < ACTION_MIN || ACTION_MAX <= action) {
            continue;
        }
#ifdef NDEBUG // for cmake's release mode
        if (action == ACTION_DEBUG) {
            fprintf(stderr, "Someone failed to call dnser_debug(%p)\n", actions[ACTION_DEBUG]);
            assert(0);
        }
#endif

        action_fn = actions[action];
        if (action_fn == 0) {
            continue;
        }
        set_ctx_state(state);
        action_fn(buf);
    } while (1);

    return 0;
}
