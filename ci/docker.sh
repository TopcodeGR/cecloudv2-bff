docker build  --no-cache \
  --build-arg REPOSILITE_USERNAME=$REPOSILITE_USERNAME \
  --build-arg REPOSILITE_PASSWORD=$REPOSILITE_PASSWORD \
  -t registry.digitalocean.com/topcode/cecloudv2-bff:$RELEASE_BRANCH .

docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD  $DOCKER_URL

docker push registry.digitalocean.com/topcode/cecloudv2-bff:$RELEASE_BRANCH
