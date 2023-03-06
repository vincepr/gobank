# RESTful API with a postgres db (that runs in a dockercontainer)

## setting up a quick postgres db
- docker img from: https://hub.docker.com/_/postgres
`sudo docker run --name some-postgres -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres`

- check if its running `sudo docker ps`

- once created start the container with : `sudo docker start some-postgres`

- stop and remove: `sudo docker stop some-postgres && sudo docker rm -f some-postgres`

## auth
- bcrypt to encrypt passwords: `golang.org/x/crypto/bcrypt`
- jwt-web-token standard using `github.com/golang-jwt/jwt/v5` for access/auth