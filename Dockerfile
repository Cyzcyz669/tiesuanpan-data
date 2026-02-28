# ── 构建阶段 ──────────────────────────────────────────
FROM rust:slim AS builder

WORKDIR /app

# 先复制依赖文件，利用 Docker 层缓存
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs
RUN cargo build --release 2>/dev/null || true

# 复制真实源码，增量编译
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ── 运行阶段（最小镜像）──────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/iron_abacus /usr/local/bin/iron_abacus

# 监听 0.0.0.0（容器内必须，不能用 127.0.0.1）
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080

CMD ["iron_abacus"]
