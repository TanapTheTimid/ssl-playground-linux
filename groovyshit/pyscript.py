import sys
import pafy

vid = pafy.new(sys.argv[1])
print(vid.getbestaudio(preftype="m4a").url, flush=True)