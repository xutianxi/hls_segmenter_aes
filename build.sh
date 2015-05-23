rm -rf segmenter
gcc -Wall -g -I/usr/local/ffmpeg/include aes.c m3u8-segmenter.c -o segmenter -L/usr/local/ffmpeg/lib -lavformat
cp -f segmenter ../
