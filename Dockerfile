FROM node:12-alpine

# Deis wants bash
RUN apk update && apk add bash
RUN apk add git

# Bundle app source
WORKDIR /usr/src/groundtruth
COPY . /usr/src/groundtruth

# Set Timezone to EST
RUN apk add tzdata
ENV TZ="/usr/share/zoneinfo/America/New_York"

RUN yarn install

ENV NODE_ENV="production"

RUN yarn build

FROM node:12-alpine
WORKDIR /usr/src/groundtruth
COPY --from=0 /usr/src/groundtruth .
EXPOSE 3000
CMD ["yarn", "start"]
