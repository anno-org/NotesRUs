FROM node:latest as frontend
WORKDIR /usr/app
COPY ./notes_r_us_ui/ ./notes_r_us_ui/
WORKDIR /usr/app/notes_r_us_ui/
RUN npm i && npm run build

FROM rust:1.84.1 as api
WORKDIR /usr/app
COPY . .
RUN cargo build

FROM debian:latest as server
WORKDIR /usr/app
COPY --from=frontend /usr/app/notes_r_us_ui/dist ./notes_r_us_ui/dist
COPY --from=api usr/app/target/debug/notes_r_us ./notes_r_us
RUN touch database.sqlite # default local database without presistance
EXPOSE 3000
CMD ["/usr/app/notes_r_us"]
