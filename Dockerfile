FROM node:11-alpine
MAINTAINER Ryan Petschek <petschekr@gmail.com>

ARG BUGSNAG

# Deis wants bash
RUN apk update && apk add bash
RUN apk add git

# Bundle app source
WORKDIR /usr/src/groundtruth
COPY . /usr/src/groundtruth

# Set Timezone to EST
RUN apk add tzdata
ENV TZ="/usr/share/zoneinfo/America/New_York"
ENV NODE_ENV="production"

RUN npm install
RUN npm run build

# Report a release to Bugsnag
RUN npm run report-build

FROM node:11-alpine
WORKDIR /usr/src/groundtruth
COPY --from=0 . .
EXPOSE 3000
CMD ["npm", "start"]
