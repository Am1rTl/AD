#ifndef DNSER_UTILS_H
#define DNSER_UTILS_H

#define STR_(x) #x
#define STR(x) STR_(x)
#define UNREACHABLE() do{fprintf(stderr, "It's unreachable %s:%d\n", __FILE__, __LINE__); exit(EXIT_FAILURE);}while(0)

#endif //DNSER_UTILS_H
