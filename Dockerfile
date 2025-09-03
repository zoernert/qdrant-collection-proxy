FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY src ./src
COPY scripts ./scripts
COPY README.md .
ENV NODE_ENV=production
EXPOSE 8787
CMD ["node", "src/server.js"]
