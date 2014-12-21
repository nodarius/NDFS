#ifndef LOGGER_H
#define LOGGER_H

#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define clean_errno() (errno == 0 ? "Success" : strerror(errno))


#define log_emerg(M, ...)						\
	syslog(LOG_EMERG, "<EMERGENCY> (%s:%d: errno: %s) \n"		\
	       M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_alert(M, ...) syslog(LOG_ALERT, "<ALERT> (%s:%d: errno: %s) \n" \
				 M "\n", __FILE__, __LINE__, clean_errno(), \
				 ##__VA_ARGS__)

#define log_crit(M, ...) syslog(LOG_CRIT, "<CRITICAL> (%s:%d: errno: %s) \n" \
				 M "\n", __FILE__, __LINE__, clean_errno(), \
				 ##__VA_ARGS__)

#define log_error(M, ...) syslog(LOG_ERR, "<ERROR> (%s:%d: errno: %s) \n" \
				 M "\n", __FILE__, __LINE__, clean_errno(), \
				 ##__VA_ARGS__)

#define log_warning(M, ...)						\
	syslog(LOG_WARNING, "<WARNING> (%s:%d: errno: %s) \n"		\
		M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_notice(M, ...) syslog(LOG_NOTICE, "<NOTICE> (%s:%d: errno: %s) \n" \
				  M "\n", __FILE__, __LINE__, clean_errno(), \
				  ##__VA_ARGS__)

#define log_info(M, ...) syslog(LOG_INFO, "<INFO> (%s:%d: errno: %s) \n" \
				  M "\n", __FILE__, __LINE__, clean_errno(), \
				  ##__VA_ARGS__)

#define log_function(M, ...) syslog(LOG_INFO,				\
				    "<FUNCTION> (%s:%s) \n" M "\n", \
				    __FILE__, __FUNCTION__, ##__VA_ARGS__)



#define log_debug(M, ...) syslog(LOG_DEBUG, "<DEBUG> (%s:%d: errno: %s) \n" \
				  M "\n", __FILE__, __LINE__, clean_errno(), \
				  ##__VA_ARGS__)



#define check(A, M, ...) if(!(A)) { log_error(M, ##__VA_ARGS__); errno=0;}

#define check_kill(A, M, ...) if(!(A)) { log_error(M, ##__VA_ARGS__); errno=0; \
		exit(-1);}


#define check_null(A) check_kill((A), "NULL pointer error.")
#define check_mem(A) check_kill((A), "Out of memory.")
#define sentinel(M, ...)  { check_kill(0, M, ##__VA_ARGS__); errno=0; }


#endif

