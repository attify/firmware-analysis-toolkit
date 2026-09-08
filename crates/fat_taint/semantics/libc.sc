// fat_taint method semantics: libc
// Format: "function_name" param_index->param_index
// -1 = return value

// Command execution sinks
"system" 1->1
"popen" 1->1
"execl" 1->1
"execlp" 1->1
"execv" 1->1
"execve" 1->1

// String operations (src → dst)
"strcpy" 2->1
"strncpy" 2->1
"strcat" 2->1
"strncat" 2->1
"memcpy" 2->1
"memmove" 2->1

// Format string (format args → buffer)
"sprintf" 2->1
"snprintf" 3->1
"fprintf" 2->1

// Input functions (return → buffer)
"fgets" -1->1
"fread" -1->1
"read" -1->2
"recv" -1->2

// Environment (return is tainted)
"getenv" -1->-1

// Allocation (size, no taint propagation to content)
"malloc" PASSTHROUGH_NONE
"calloc" PASSTHROUGH_NONE
"free" PASSTHROUGH_NONE
