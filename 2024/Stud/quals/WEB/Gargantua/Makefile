SRC = "src"
HANDOUT = "gargantua.tar"

build:
	docker compose up --build

generate_handout:
	tar cf $(HANDOUT) $(SRC) "docker-compose.yaml"

clean:
	rm $(HANDOUT)
