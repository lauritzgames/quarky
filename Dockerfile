FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .
RUN mkdir -p /app/files && chown -R node:node /app

ENV NODE_ENV=production
EXPOSE 3000

USER node
CMD ["node", "index.js"]
