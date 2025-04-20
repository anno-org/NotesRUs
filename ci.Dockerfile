FROM debian:latest
WORKDIR /usr/app

# TODO: add new ui
# COPY ./notes_r_us_ui/ ./notes_r_us_ui/dist

# Get api binary
COPY ./notes_r_us/notes_r_us ./notes_r_us

# can be run without external database
RUN touch database.sqlite

RUN chmod +x ./notes_r_us
EXPOSE 3000
CMD ["/usr/app/notes_r_us"]
