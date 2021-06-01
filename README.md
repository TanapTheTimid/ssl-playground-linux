# ssl-playground-linux

Requirements:

sudo apt-get install build-essential openssl libssl-dev libssl1.1 libcrypto python3 ffmpeg

also run:
python3 -m pip install youtube-dl pafy

ffmpeg can do cool piping stuff:
cat Happy\ Bite.m4a | ffmpeg -i pipe:0 -f mp3 pipe:1 | cat > test.mp3

this means we can use pipes to feed into child process running ffmpeg and also pipe out from it into discord