#!/usr/bin/env bash
# Junta a gravacao de tela (muda) com a narracao de audio gravada a parte.
#
# Uso:
#   docs/juntar_video_audio.sh tela.webm audio.m4a saida.mp4 [offset_audio_s]
#
# offset_audio_s (opcional, pode ser negativo): atraso do audio em relacao
# ao video, em segundos, se as duas gravacoes nao comecarem no mesmo instante.
# Ex: se o audio comeca 1.5s depois do video, use 1.5.
set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "Uso: $0 <video> <audio> <saida.mp4> [offset_audio_s]" >&2
    exit 1
fi

VIDEO="$1"
AUDIO="$2"
SAIDA="$3"
OFFSET="${4:-0}"

if [ ! -f "$VIDEO" ]; then
    echo "Video nao encontrado: $VIDEO" >&2
    exit 1
fi
if [ ! -f "$AUDIO" ]; then
    echo "Audio nao encontrado: $AUDIO" >&2
    exit 1
fi

ffmpeg -y \
    -i "$VIDEO" \
    -itsoffset "$OFFSET" -i "$AUDIO" \
    -map 0:v:0 -map 1:a:0 \
    -c:v libx264 -preset veryfast -crf 20 -profile:v baseline -level 3.0 \
    -pix_fmt yuv420p -c:a aac -b:a 160k \
    -shortest \
    "$SAIDA"

echo "OK: $SAIDA"
