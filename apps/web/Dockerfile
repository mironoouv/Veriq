FROM node:24.13.1-bookworm-slim@sha256:a81a03dd965b4052269a57fac857004022b522a4bf06e7a739e25e18bce45af2 AS dependencies
WORKDIR /app
RUN chown node:node /app
USER node
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

FROM dependencies AS development
COPY --chown=node:node . .
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--strictPort"]

FROM dependencies AS build
COPY --chown=node:node index.html tsconfig.json vite.config.ts ./
COPY --chown=node:node src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31.7-alpine@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e AS production
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
