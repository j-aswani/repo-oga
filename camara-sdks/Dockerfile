FROM node:18.16.0-alpine3.17

RUN apk add --no-cache curl
RUN apk add --no-cache git make clang build-base python3
RUN npm install -g pnpm@8.5.1

WORKDIR /apps

COPY package.json pnpm-lock.yaml tsconfig.base.json tsconfig.json pnpm-workspace.yaml nx.json babel.config.json ./

ADD examples ./examples

ADD sdks ./sdks

RUN pnpm install --frozen-lockfile

WORKDIR /apps/examples/express-demo-app

CMD [ "npm", "run", "start:pro" ]
