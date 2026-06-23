# HaloSusu — Node 22 (built-in node:sqlite, no dependencies)
FROM node:22-alpine
WORKDIR /app

# no npm install needed — the app has zero dependencies
COPY . .

# Railway injects PORT at runtime; the app listens on process.env.PORT
EXPOSE 3000
CMD ["node", "server.js"]
