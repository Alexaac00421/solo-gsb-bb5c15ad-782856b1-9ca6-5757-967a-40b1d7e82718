FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production

# Install dependencies first for better layer caching
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Application source
COPY src ./src
COPY db ./db
COPY public ./public

EXPOSE 3000

CMD ["node", "src/server.js"]
