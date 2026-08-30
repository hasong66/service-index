FROM python:3.12-slim

# OCI 标准标签：别人 docker inspect 时能看清这镜像是什么、哪来的。
# 版本号由构建时传入：docker build --build-arg VERSION=1.0.0 ...；不传就是 dev。
ARG VERSION=dev
LABEL org.opencontainers.image.title="Service Index" \
      org.opencontainers.image.description="网络感知的自托管服务导航页：按你访问用的地址自动跳到对应网络下的服务地址，并能扫描端口自动识别服务" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/hasong66/service-index" \
      org.opencontainers.image.licenses="MIT"

# 不写 .pyc、日志实时输出
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CONFIG_PATH=/data/config.yaml \
    PORT=5000

WORKDIR /app

# 先装依赖，利用 Docker 层缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 再拷贝应用代码
COPY app.py .
COPY discover.py .
COPY templates ./templates
COPY static ./static

# 配置文件（含密码哈希）持久化到数据卷
VOLUME ["/data"]
EXPOSE 5000

# 镜像里没有 curl，用 python 自带的 urllib 探活即可。
# /api/status 不需要登录，且会真正读一次配置文件，比探 TCP 端口有意义。
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/status', timeout=4).status == 200 else 1)"

# 说明：容器以 root 运行。这是有意的 —— 换成非 root 会让 `-v ./data:/data` 这种
# 绑定挂载在多数人机器上直接写不了配置文件（宿主目录通常是 root 或另一个 uid 所有），
# 是自托管镜像里最常见的踩坑点。容器内不监听除 5000 外的端口，也不需要额外能力。
#
# --preload：先在主进程加载一次 app（生成/读取同一个 secret_key），
# 再 fork 出 worker，避免多 worker 各自生成不同 secret_key 导致会话失效。
# --threads：端口发现是个长连接（SSE），扫全端口能跑一两分钟。用线程工作模式，
#            扫描期间同一个 worker 还能继续处理别的请求。
# --timeout：默认 30 秒会把还在扫描的 worker 判死，放宽到 5 分钟。
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "--threads", "8", "--timeout", "300", "--preload", "app:app"]
