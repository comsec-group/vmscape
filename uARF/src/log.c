#include "log.h"

// Any log with a level higher than this is shown, regardless of the tag
UarfLogLevel uarf_log_system_base_level = UARF_LOG_LEVEL_INFO;

// Show any log associated with this tag and a level higher than this
// UarfLogLevel uarf_log_system_level = UARF_LOG_LEVEL_TRACE;
UarfLogLevel uarf_log_system_level = UARF_LOG_LEVEL_ERROR;

UarfLogTag uarf_log_system_tag = UARF_LOG_TAG_TEST;
// UarfLogTag uarf_log_system_tag = UARF_LOG_TAG_ALL;
