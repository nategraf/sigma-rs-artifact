#ifndef OONIAUTH_FFI_H
#define OONIAUTH_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

char *ooniauth_run_basic_usage(void);
char *ooniauth_run_benchmarks(void);
void ooniauth_string_free(char *ptr);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OONIAUTH_FFI_H
