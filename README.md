# Ghosted - A PoC on Process Ghosting

## Introduction
`Process Ghosting` is a technique of running EXE payloads that has already been deleted. On Windows. it is possible to create a file, put it in a delete pending stage, write your payload to it, map it to an image section for it, close the file handle to delete the file and then finally create a process from the mapped image section. This, essentially, is the `Process Ghosting` process.  In this way, the created process does not have an associated executable file on disk which makes detections difficult for certain EDRs/AV engines.

![Process Ghosting](./img/PoC_Ghosting.png)

## Processes Spawned Up, Callbacks Thrown Up [🎵](https://www.youtube.com/shorts/XO5gYTHo6HI)


An interesting question to ask is how do Security vendors scan processes? One of the methods, [as described my Microsoft in this post](https://www.microsoft.com/en-us/security/blog/2022/06/30/using-process-creation-properties-to-catch-evasion-techniques/), goes as follows:

> Process creation callbacks in the kernel, such as those provided by the [_PsSetCreateProcessNotifyRoutineEx_](https://docs.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex) API, is the functionality in the operating system that allows antimalware engines to inspect a process while it’s being created. It can intercept the creation of a process and perform a scan on the relevant executable, all before the process runs.

However, there is a catch. Looking at the documentation for [`PsSetCreateProcessNotifyRoutineEx`](https://docs.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex), notice the following part:

> When a process is created, the process-notify routine runs in the context of the thread that created the new process. When a process is deleted, the process-notify routine runs in the context of the last thread to exit from the process.

This means that callbacks are registered only when the first thread is spawned, which gives malware a window between time of creation and the time at which security vendors are notified about it. It is in this interval that malware can carry out image tampering leading to attacks like `Process Doppelgänging`, `Process Herpaderping` and `Process Ghosting`.

## Show and Tell

## References
- https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack