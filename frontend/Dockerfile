# Build the static bundle, then serve it from nginx.
# The previous image ran `vite dev` in production, which is a development server:
# unminified, single-threaded, and not built to face traffic.

FROM node:22-alpine AS build
WORKDIR /app

# Vite inlines the API base URL at build time, so it has to be a build arg.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL

COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:5173/ >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
