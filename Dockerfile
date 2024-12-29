FROM node:slim AS builder
RUN apt-get update || : && apt-get install -y python3 build-essential
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

FROM node:alpine
LABEL Maintainer Michael Shihjay Chen <shihjay2@gmail.com>
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/*.mjs ./
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/public ./public
COPY --from=builder /usr/src/app/views ./views
COPY --from=builder /usr/src/app/proxy ./proxy
EXPOSE 4000
CMD ["node", "index.mjs"]