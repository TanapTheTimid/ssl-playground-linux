# ssl-playground-linux

Requirements:

sudo apt-get install build-essential openssl libssl-dev libssl1.1 libcrypto python3 ffmpeg

also run:
python3 -m pip install youtube-dl pafy

ffmpeg can do cool piping stuff:
cat Happy\ Bite.m4a | ffmpeg -i pipe:0 -f mp3 pipe:1 | cat > test.mp3

this means we can use pipes to feed into child process running ffmpeg and also pipe out from it into discord


ffmpeg -i input.mp3 -c:a libopus -b:a 32k -vbr on -compression_level 10 -frame_duration 60 -application voip output.opus


ffmpeg -i input.m4a -c:a libopus -b:a 64k -vbr on -compression_level 10 -frame_duration 60 -application audio output.opus


./discord 'singapore756.discord.media' '/?v=4' '{"op": 3,"d": 1501184119560}' '"op":8'

./discord 'gateway.discord.gg' '/?v=9&encoding=json' '{"op": 1,"d": {},"s": null,"t": null}' '"op":10'