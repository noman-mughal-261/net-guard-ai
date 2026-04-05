FROM node:20-alpine AS build
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
ARG VITE_API_BASE=
ENV VITE_API_BASE=$VITE_API_BASE
ARG VITE_BLOCK_API_KEY=
ENV VITE_BLOCK_API_KEY=$VITE_BLOCK_API_KEY
RUN npm run build

FROM nginx:alpine
COPY --from=build /ui/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
