// Compile the unmodified MIT-licensed inflater as C++ in the Windows-only build.
// The ZIP parser, path policy, limits and output writes are owned by FuzeVPN.
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_DEFLATE_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_LITTLE_ENDIAN 1
#include "../../third_party/miniz/miniz_tinfl.c"
