#pragma once
#include "compiler.h"
#include <limits.h>

#include <stdio.h>

#define _UARF_ANSI_SEQ(n) "\033[" #n "m"

#define UARF_LOG_C_RESET        _UARF_ANSI_SEQ(0)
#define UARF_LOG_C_BLACK        _UARF_ANSI_SEQ(30)
#define UARF_LOG_C_DARK_RED     _UARF_ANSI_SEQ(31)
#define UARF_LOG_C_DARK_GREEN   _UARF_ANSI_SEQ(32)
#define UARF_LOG_C_DARK_YELLOW  _UARF_ANSI_SEQ(33)
#define UARF_LOG_C_DARK_BLUE    _UARF_ANSI_SEQ(34)
#define UARF_LOG_C_DARK_PINK    _UARF_ANSI_SEQ(35)
#define UARF_LOG_C_DARK_CYAN    _UARF_ANSI_SEQ(36)
#define UARF_LOG_C_GRAY         _UARF_ANSI_SEQ(90)
#define UARF_LOG_C_LIGHT_RED    _UARF_ANSI_SEQ(91)
#define UARF_LOG_C_LIGHT_GREEN  _UARF_ANSI_SEQ(92)
#define UARF_LOG_C_LIGHT_YELLOW _UARF_ANSI_SEQ(93)
#define UARF_LOG_C_LIGHT_BLUE   _UARF_ANSI_SEQ(94)
#define UARF_LOG_C_LIGHT_PINK   _UARF_ANSI_SEQ(95)
#define UARF_LOG_C_LIGHT_CYAN   _UARF_ANSI_SEQ(96)
#define UARF_LOG_C_LIGHT_GRAY   _UARF_ANSI_SEQ(97)

// Holds all logging levels
typedef enum UarfLogLevel UarfLogLevel;
enum UarfLogLevel {
    UARF_LOG_LEVEL_TRACE = 0,
    UARF_LOG_LEVEL_DEBUG = 1,
    UARF_LOG_LEVEL_INFO = 2,
    UARF_LOG_LEVEL_WARNING = 3,
    UARF_LOG_LEVEL_ERROR = 4,
};

// Holds all available logging tags
typedef enum UarfLogTag UarfLogTag;
enum UarfLogTag {
    UARF_LOG_TAG_NONE = 0,
    UARF_LOG_TAG_MEM = BIT(1),
    UARF_LOG_TAG_TEST = BIT(1),
    UARF_LOG_TAG_JITA = BIT(2),
    UARF_LOG_TAG_VSNIP = BIT(3),
    UARF_LOG_TAG_PSNIP = BIT(4),
    UARF_LOG_TAG_STUB = BIT(5),
    UARF_LOG_TAG_FR = BIT(6),
    UARF_LOG_TAG_PFC = BIT(7),
    UARF_LOG_TAG_GUEST = BIT(8),
    UARF_LOG_TAG_APP = BIT(9),
    UARF_LOG_TAG_DLL = BIT(10),
    UARF_LOG_TAG_ALL = ULONG_MAX,
};

// Any log with a level higher than this is shown, regardless of the tag
extern UarfLogLevel uarf_log_system_base_level;
// Show any log associated with this tag and a level higher than this
extern UarfLogLevel uarf_log_system_level;
extern UarfLogTag uarf_log_system_tag;

// Default tag, overwrite in each file
// Do not modifie here!
#define UARF_LOG_TAG UARF_LOG_TAG_APP

#define UARF_LOG_LOG(print_f, level, tag, prefix, color, format, ...)                    \
    ({                                                                                   \
        if (level >= uarf_log_system_base_level ||                                       \
            (level >= uarf_log_system_level && (tag & uarf_log_system_tag) != 0)) {      \
            print_f(color "[%s] %s:%d:%s " format UARF_LOG_C_RESET, prefix, __FILE__,    \
                    __LINE__, __func__ __VA_OPT__(, ) __VA_ARGS__);                      \
        }                                                                                \
    })

#define UARF_LOG_TRACE(format, ...)                                                      \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_TRACE, UARF_LOG_TAG, "TRACE",                    \
                 UARF_LOG_C_LIGHT_GREEN, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_DEBUG(format, ...)                                                      \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_DEBUG, UARF_LOG_TAG, "DEBUG",                    \
                 UARF_LOG_C_LIGHT_BLUE, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_INFO(format, ...)                                                       \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_INFO, UARF_LOG_TAG, "INFO",                      \
                 UARF_LOG_C_LIGHT_PINK, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_WARNING(format, ...)                                                    \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_WARNING, UARF_LOG_TAG, "WARNING",                \
                 UARF_LOG_C_DARK_YELLOW, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_ERROR(format, ...)                                                      \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_ERROR, UARF_LOG_TAG, "ERROR",                    \
                 UARF_LOG_C_DARK_RED, format __VA_OPT__(, ) __VA_ARGS__)

#define UARF_LOG_TRACE_U(format, ...)                                                    \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_TRACE, UARF_LOG_TAG, "TRACE",                    \
                 UARF_LOG_C_LIGHT_GREEN, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_DEBUG_U(format, ...)                                                    \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_DEBUG, UARF_LOG_TAG, "DEBUG",                    \
                 UARF_LOG_C_LIGHT_BLUE, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_INFO_U(format, ...)                                                     \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_INFO, UARF_LOG_TAG, "INFO",                      \
                 UARF_LOG_C_LIGHT_PINK, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_WARNING_U(format, ...)                                                  \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_WARNING, UARF_LOG_TAG, "WARNING",                \
                 UARF_LOG_C_DARK_YELLOW, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_LOG_ERROR_U(format, ...)                                                    \
    UARF_LOG_LOG(printf, UARF_LOG_LEVEL_ERROR, UARF_LOG_TAG, "ERROR",                    \
                 UARF_LOG_C_DARK_RED, format __VA_OPT__(, ) __VA_ARGS__)
#define UARF_HERE()                                                                      \
    printf(UARF_LOG_C_DARK_RED "%s, %s, %u\n" UARF_LOG_C_RESET, __FILE__, __func__,      \
           __LINE__)
