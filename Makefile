scripts = usefulScripts
dataFolder = comiFolder
files = ${dataFolder}/files
data = ${dataFolder}/comiData

install:
	./${scripts}/installFS.sh

build:
	./${scripts}/makeFolder.sh
	./${scripts}/systemInit.sh ${data} ${files}

all: build run

run:
	./${scripts}/mountFolder.sh 

clean:
	rm -rf *Folder
	rm comiFS*

restore:
	./${scripts}/restoreFiles.sh dataFolder