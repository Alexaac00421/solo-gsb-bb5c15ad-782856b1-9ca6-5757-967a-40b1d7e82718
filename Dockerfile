FROM node:20-alpine

WORKDIR /app

# 先装依赖，利用层缓存
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY src ./src
COPY scripts ./scripts
COPY public ./public

# 等待数据库 → 建表/初始管理员 → 启动 Web
RUN printf \
'#!/bin/sh\nset -e\nnode scripts/init-db.js\nexec node src/server.js\n' > /usr/local/bin/start.sh \
  && chmod +x /usr/local/bin/start.sh

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/start.sh"]
