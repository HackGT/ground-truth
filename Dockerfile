FROM node:11-alpine
MAINTAINER Ryan Petschek <petschekr@gmail.com>

# Deis wants bash
RUN apk update && apk add bash
RUN apk add git

# Bundle app source
WORKDIR /usr/src/groundtruth
COPY . /usr/src/groundtruth

# Set Timezone to EST
RUN apk add tzdata
ENV TZ="/usr/share/zoneinfo/America/New_York"

RUN npm install
RUN npm run build

# Report a release to Bugsnag
RUN npm run report-build

EXPOSE 3000
CMD ["npm", "start"]
