# 多阶段构建：编译阶段
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /build

# 使用国内 Go 代理加速依赖下载
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o cmux-relay .

# 运行阶段：最小化镜像
FROM alpine:3.21

RUN apk add --no-cache sqlite-libs ca-certificates tzdata

# 以非 root 用户运行
RUN adduser -D -u 1000 relay
USER relay

WORKDIR /app
COPY --from=builder /build/cmux-relay .

# 数据目录（挂载卷）
RUN mkdir -p /app/data

EXPOSE 8443

# 默认参数，可通过 docker-compose 或 docker run 覆盖
ENTRYPOINT ["./cmux-relay"]
CMD ["-addr", ":8443", "-db", "/app/data/cmux-relay.db"]
