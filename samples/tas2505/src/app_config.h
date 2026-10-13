#ifndef __APP_CONFIG__
#define __APP_CONFIG__

#ifndef PLAYBACK_LOOP
#define PLAYBACK_LOOP           0
#endif

#ifndef FRAME_CLK_HZ
#define FRAME_CLK_HZ            16000
#endif

#ifndef WORD_SIZE_BITS
#define WORD_SIZE_BITS          16
#endif

/* Channel routing IDs -- keep in sync with CMakeLists.txt. */
#define CHANNEL_MODE_MONO_LEFT  1
#define CHANNEL_MODE_MONO_RIGHT 2

#ifndef CHANNEL_MODE_ID
#define CHANNEL_MODE_ID         CHANNEL_MODE_MONO_RIGHT
#endif
#ifndef CHANNEL_MODE_NAME
#define CHANNEL_MODE_NAME       "mono_right"
#endif

#ifndef PLAYBACK_MODE_NAME
#define PLAYBACK_MODE_NAME      "one_shot"
#endif

#ifndef PLAYBACK_SECONDS
#define PLAYBACK_SECONDS        30
#endif

#endif // __APP_CONFIG__