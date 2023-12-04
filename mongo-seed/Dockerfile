FROM mongo:5.0

ADD ./localhost /localhost
ADD ./azure /azure
ADD ./docker-entrypoint.sh /docker-entrypoint.sh
ADD ./wait-for-it.sh /wait-for-it.sh

RUN apt-get update && apt-get install -y curl

ENTRYPOINT [ "./wait-for-it.sh", "-t", "60", "mongodb:27017", "--", "./docker-entrypoint.sh"]
