# Ghosted - A PoC on Process Ghosting

## Introduction
`Process Ghosting` is a technique of running EXE payloads that has already been deleted. On Windows. it is possible to create a file, put it in a delete pending stage, write your payload to it, map it to an image section for it, close the file handle to delete the file and then finally create a process from the mapped image section. This, essentially, is the `Process Ghosting` process.  In this way, the created process does not have an associated executable file on disk which makes detections difficult for certain EDRs/AV engines.

![Process Ghosting](./img/PoC\ Ghosting.png)

## A word about Processes


## References
- https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack