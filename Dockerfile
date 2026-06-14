FROM python:3.11-slim

LABEL maintainer="SecOps Team"
LABEL description="SecOps 自动化安全运维工具箱"

WORKDIR /app

# 系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY secops-core/ /app/secops-core/
COPY secops-offense/ /app/secops-offense/
COPY secops-defense/ /app/secops-defense/
COPY secops-cli/ /app/secops-cli/
COPY pyproject.toml /app/

# 安装 Python 依赖
RUN pip install --no-cache-dir -e /app/secops-core/ \
    && pip install --no-cache-dir -e /app/secops-offense/ \
    && pip install --no-cache-dir -e /app/secops-defense/ \
    && pip install --no-cache-dir -e /app/secops-cli/

# 创建必要的目录
RUN mkdir -p /root/.secops/cache /root/.secops/logs /app/reports

# 设置环境变量
ENV SECOPS_CACHE_DIR=/root/.secops/cache
ENV SECOPS_LOG_DIR=/root/.secops/logs
ENV SECOPS_REPORT_DIR=/app/reports

EXPOSE 22

ENTRYPOINT ["secops"]
CMD ["--help"]
