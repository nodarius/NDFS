#include "common.h"

char *get_parent_path(const char *path)
{
	check_null(path != NULL);
	int len = strlen(path);
	check_kill(len > 0 && path[0] == '/', "invalid path");

	log_function("path is: %s", path);
	int first_slash = -1;
	int last_slash = -1;

	if (path[len - 1] == '/')
		len--;
	int i;
	for (i = 0; i < len; i++) {
		if (path[i] == '/') {
			if (first_slash == -1)
				first_slash = i;
			last_slash = i;
		}
	}

	len = last_slash - first_slash + 1;
	char *result = malloc(len + 1);
	check_mem(result);
	result[len] = '\0';
	memcpy(result, path, len);

	return result;
}
