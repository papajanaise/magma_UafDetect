#ifndef GCC_CLANG_SHIM_H
#define GCC_CLANG_SHIM_H

/* Stubs for clang-only builtins so libjpeg-turbo's fuzz harnesses compile
 * under gcc. Each predicate defaults to 0 ("feature not present"), matching
 * the false branch the harness would take under non-instrumented clang. */

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#endif
