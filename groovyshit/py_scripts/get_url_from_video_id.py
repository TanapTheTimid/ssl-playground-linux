import sys
import pafy

YOUTUBE_VIDEO_URL_PREFIX = "https://www.youtube.com/watch?v="

vid = pafy.new(YOUTUBE_VIDEO_URL_PREFIX + sys.argv[1])
print(vid.getbestaudio(preftype="m4a").url, flush=True)
print(vid.title, flush=True)