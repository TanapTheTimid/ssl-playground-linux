# ssl-playground-linux

Requirements:

sudo apt-get install build-essential openssl libssl-dev libssl1.1 libcrypto python3 ffmpeg libsodium-dev libopus0 libopus-dev libogg-dev opus-tools

also run:
python3 -m pip install youtube-dl pafy

ffmpeg can do cool piping stuff:
cat Happy\ Bite.m4a | ffmpeg -i pipe:0 -f mp3 pipe:1 | cat > test.mp3

this means we can use pipes to feed into child process running ffmpeg and also pipe out from it into discord


ffmpeg -i input.mp3 -c:a libopus -b:a 32k -vbr on -compression_level 10 -frame_duration 60 -application voip output.opus


ffmpeg -i input.m4a -c:a libopus -b:a 64k -vbr on -compression_level 10 -frame_duration 60 -application audio output.opus

ffmpeg -i input.m4a -c:a libopus -b:a 64k -vbr off -compression_level 10 -frame_duration 60 -application audio output.opus



ffmpeg -i input.m4a -c:a libopus -b:a 64k -vbr off -compression_level 4 -frame_duration 20 -application audio testingfile.ogg


./discord 'singapore756.discord.media' '/?v=4' '{"op": 3,"d": 1501184119560}' '"op":8'

./discord 'gateway.discord.gg' '/?v=9&encoding=json' '{"op": 1,"d": {},"s": null,"t": null}' '"op":10'

https://stackoverflow.com/questions/43656892/stream-opus-audio-rtp-to-android-device

https://stackoverflow.com/questions/59562598/ffmpeg-command-to-gstreamer-pipeline-for-srtp-stream


ffmpeg -ss 00:01:00.00 -i -c:a libopus -b:a 64k -vbr off -compression_level 4 -frame_duration 20 -application audio testingfile.ogg

char *new_argv[30] = {
                  "ffmpeg"
                , "-ss"
                , "00:01:00.00"
                , "-i"
                , "..url.."
                , "-c:a"
                , "libopus"
                , "-b:a"
                , "64k"
                , "-vbr"
                , "off"
                , "-compression_level"
                , "4"
                , "-frame_duration"
                , "20"
                , "-application"
                , "audio"
                , "testingfile.ogg"
                , 0};



char *new_argv[50] = {
                  "ffmpeg"
                , "-ss"                 , "00:00:00.00"
                //////, "-f" , "m4a" , "-dn" , "-ignore_unknown" , "-copyts" , "-err_detect" , "ignore_err"
                , "-i"                  , "..url.."
                , "-c:a"                , "libopus"
                , "-b:a"                , "64k"
                , "-vbr"                , "off"
                , "-compression_level"  , "4"
                , "-frame_duration"     , "20"
                , "-application"        , "audio"
                , "-f"                  , "ogg"
                , "-y"
                , "audiostream.file.out"
                , 0};




char *new_argv[50] = {
                  "ffmpeg"
                , "-ss"                 , "00:00:00.00"
                , "-i"                  , "..url.."
                , "-c:a"                , "libopus"
                , "-b:a"                , "64k"
                , "-vbr"                , "off"

                , "-packet_loss"        , "20"
                , "-fec"                , "on"

                , "-compression_level"  , "4"
                , "-frame_duration"     , "20"
                , "-application"        , "audio"
                , "-f"                  , "ogg"
                , "-y"
                , "audiostream.file.out"
                , 0};