#!/bin/bash
# Run this ONLY when you have manually changed the code and want to update the
# build running INSIDE the existing Docker container.
# It rebuilds locally, copies the new binary + frontend into the container,
# and restarts the container.
# For image changes, use: docker compose up -d --build

cd /home/void/clones/Reconner
make

sudo docker cp /home/void/clones/Reconner/frontend/dist/. reconner:/opt/reconner/frontend/dist/
sudo docker exec -u root reconner chown -R reconner:reconner /opt/reconner/frontend/dist

sudo docker cp /home/void/clones/Reconner/reconner reconner:/usr/local/bin/reconner
sudo docker exec -u root reconner chown reconner:reconner /usr/local/bin/reconner

sudo docker restart reconner
