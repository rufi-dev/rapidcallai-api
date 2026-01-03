FROM node:20-alpine
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY env.example ./env.example

EXPOSE 8787
CMD ["node", "src/index.js"]

