To update the AV run the following:
===================================

```bash
$ docker run --name=avg malice/avg update
```

Then to use the updated AVG container:
--------------------------------------

```bash
$ docker commit avg malice/avg:updated
$ docker rm avg # clean up updated container
$ docker run --rm malice/avg:updated EICAR
```
