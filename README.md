# 

## setting up a quick postgres db
- docker img from: https://hub.docker.com/_/postgres
`docker run --name some-postgres -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres`

- check if its running `docker ps`