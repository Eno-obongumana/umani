IMAGE=umani:latest

.PHONY: build run test scan shell clean

build:
	docker build -t $(IMAGE) .

run:
	docker run --rm -it --network host -v umani-data:/data $(IMAGE) modules

test:
	bash demos/run-all.sh

scan:
	docker run --rm --network host -v umani-data:/data $(IMAGE) scan http://127.0.0.1:5000/

shell:
	docker run --rm -it --network host -v umani-data:/data \
	  --entrypoint /bin/bash $(IMAGE)

clean:
	docker rmi $(IMAGE) 2>/dev/null || true
	docker volume rm umani-data 2>/dev/null || true
