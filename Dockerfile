# Eye4 RTSP Proxy — Docker build
# Multi-stage: compile C accelerator, then slim runtime image

FROM python:3.12-alpine AS builder
RUN apk add --no-cache gcc musl-dev
COPY eye4_accel.c /build/
RUN gcc -O2 -shared -fPIC -o /build/eye4_accel.so /build/eye4_accel.c

FROM python:3.12-alpine
RUN apk add --no-cache ffmpeg && pip install --no-cache-dir pycryptodome pyyaml
COPY --from=builder /build/eye4_accel.so /app/
COPY eye4_rtsp_proxy.py /app/
WORKDIR /app
CMD ["python3", "eye4_rtsp_proxy.py"]
